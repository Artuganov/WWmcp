import { createHash } from "node:crypto";
import { z } from "zod";
import { oneCGet, oneCPost, buildODataPath, buildKeyedPath } from "../client.js";
import { refKeySchema } from "../validation.js";

/**
 * Присоединённые файлы 1С: прикрепить, перечислить, скачать.
 *
 * ── Как файлы устроены в базе ────────────────────────────────────────────
 *
 * Файл живёт в Catalog_<Владелец>ПрисоединенныеФайлы, ВладелецФайла_Key —
 * ссылка на документ. Сами байты хранятся одним из двух способов:
 *
 *  • «ВТомахНаДиске» — на диске тома, в карточке лежит только ПутьКФайлу.
 *    Так хранится большинство файлов этой базы. Через OData записать туда
 *    нельзя: у нас нет доступа к файловой системе сервера 1С.
 *
 *  • «ВИнформационнойБазе» — байты в Catalog_ХранилищеДвоичныхДанных, связь
 *    с карточкой через InformationRegister_ХранилищеФайлов. Это доступно по
 *    OData целиком, поэтому пишем сюда.
 *
 * Разные карточки могут ссылаться на одну запись двоичных данных: база сама
 * так делает для одинаковых файлов. Мы это повторяем — ищем по хешу и
 * переиспользуем, чтобы десять писем с одним и тем же счётом не занимали
 * место десять раз.
 *
 * Хеш — SHA-256 в base64 (проверено на живой записи: 44 символа, 32 байта).
 *
 * ── Чего этот инструмент НЕ делает ───────────────────────────────────────
 *
 * Не извлекает текст файла (СтатусИзвлеченияТекста = «НеИзвлечен») и не
 * кладёт файл в том. Полноценно это делает БСП «РаботаСФайлами.ДобавитьФайл»
 * на стороне 1С; когда появится HTTP-сервис расширения, инструмент можно
 * переключить на него, не меняя контракт. Уже загруженные файлы при этом
 * переносятся штатной обработкой «Перенос файлов в тома».
 */

/** Ссылка на пользователя — автор файла. Без него карточка выглядит ничьей. */
const DEFAULT_AUTHOR = process.env.ONEC_FILES_AUTHOR_REF?.trim() || "";

/** Предел на размер: base64 раздувает данные на треть, а ответ OData целиком в памяти. */
const MAX_BYTES = 25 * 1024 * 1024;

const ownerTypeSchema = z
  .string()
  .describe(
    "Тип владельца: Document_ЗаказПоставщику, Document_ЗаказКлиента, Catalog_Партнеры и т.п. " +
    "Каталог файлов вычисляется из него автоматически.",
  );

/**
 * Document_ЗаказПоставщику → Catalog_ЗаказПоставщикуПрисоединенныеФайлы.
 *
 * Имя каталога файлов в 1С — это имя объекта-владельца плюс суффикс, без
 * префикса типа. Отдельного справочника соответствий в конфигурации нет,
 * поэтому собираем по правилу и падаем с понятной ошибкой, если такого
 * каталога не окажется.
 */
export function filesCatalogFor(ownerType: string): string {
  const bare = ownerType.replace(/^(Document|Catalog|BusinessProcess|Task)_/i, "").trim();
  if (!bare) throw new Error(`Не понял тип владельца: «${ownerType}»`);
  return `Catalog_${bare}ПрисоединенныеФайлы`;
}

/** Расширение без точки и имя без него — 1С хранит их порознь. */
export function splitFileName(name: string): { base: string; ext: string } {
  const clean = String(name).trim().replace(/[\\/]+/g, "_");
  const dot = clean.lastIndexOf(".");
  if (dot <= 0 || dot === clean.length - 1) return { base: clean, ext: "" };
  return { base: clean.slice(0, dot), ext: clean.slice(dot + 1).toLowerCase() };
}

/** 1С ждёт дату без зоны: «2026-09-30T16:59:41». */
function odataDate(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "");
}

async function fetchSource(url: string): Promise<Buffer> {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`Файл по ссылке не отдался: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (!buf.length) throw new Error("По ссылке пришёл пустой файл");
  return buf;
}

// ──────────────────────────────────────────────────────────────
// attach_file
// ──────────────────────────────────────────────────────────────

export const attachFileSchema = z.object({
  owner_type: ownerTypeSchema,
  owner_ref_key: refKeySchema.describe("Ref_Key документа или элемента, к которому прикрепляем"),
  file_name: z.string().min(1).describe("Имя файла с расширением, например «QH-Lab3.docx»"),
  description: z.string().optional().describe("Описание файла (не имя) — попадёт в поле «Описание»"),
  content_base64: z.string().optional().describe(
    "Содержимое файла в base64. Для больших файлов лучше source_url: base64 в аргументах " +
    "раздувает запрос и упирается в лимит контекста.",
  ),
  source_url: z.string().url().optional().describe(
    "Ссылка, по которой сервер сам скачает файл (presigned S3, файл Insider и т.п.).",
  ),
  author_ref_key: refKeySchema.optional().describe(
    "Ref_Key пользователя-автора. По умолчанию берётся из ONEC_FILES_AUTHOR_REF.",
  ),
});

export async function handleAttachFile(params: z.infer<typeof attachFileSchema>): Promise<string> {
  if (!params.content_base64 && !params.source_url) {
    throw new Error("Нужно передать либо content_base64, либо source_url");
  }
  if (params.content_base64 && params.source_url) {
    throw new Error("Передано и content_base64, и source_url — оставьте что-то одно");
  }

  const bytes = params.source_url
    ? await fetchSource(params.source_url)
    : Buffer.from(params.content_base64 as string, "base64");

  if (!bytes.length) throw new Error("Пустой файл — нечего прикреплять");
  if (bytes.length > MAX_BYTES) {
    throw new Error(`Файл ${Math.round(bytes.length / 1048576)} МБ — больше предела ${MAX_BYTES / 1048576} МБ`);
  }

  const hash = createHash("sha256").update(bytes).digest("base64");
  const base64 = bytes.toString("base64");
  const { base, ext } = splitFileName(params.file_name);
  const filesCatalog = filesCatalogFor(params.owner_type);
  const author = params.author_ref_key || DEFAULT_AUTHOR;
  const now = new Date();

  // 1. Двоичные данные. Такой же файл уже мог загружаться — тогда
  //    переиспользуем запись, как это делает сама база.
  let storageKey: string;
  let reused = false;

  const existing = (await oneCGet(
    buildODataPath("Catalog_ХранилищеДвоичныхДанных", {
      $filter: `Хеш eq '${hash.replace(/'/g, "''")}'`,
      $select: "Ref_Key",
      $top: "1",
      $format: "json",
    }),
  )) as { value?: Array<{ Ref_Key?: string }> };

  if (existing?.value?.length && existing.value[0].Ref_Key) {
    storageKey = existing.value[0].Ref_Key;
    reused = true;
  } else {
    const created = (await oneCPost(
      buildODataPath("Catalog_ХранилищеДвоичныхДанных", { $format: "json" }),
      {
        ДвоичныеДанные_Type: "application/octet-stream",
        ДвоичныеДанные_Base64Data: base64,
        Хеш: hash,
        // Размер база заполняет у всех записей хранилища — проверено запросом
        // по живым данным. Без него запись выглядит битой рядом с остальными.
        Размер: String(bytes.length),
      },
    )) as { Ref_Key?: string };
    if (!created?.Ref_Key) throw new Error("1С не вернула Ref_Key записи двоичных данных");
    storageKey = created.Ref_Key;
  }

  // 2. Карточка файла.
  const card: Record<string, unknown> = {
    Description: base,
    ВладелецФайла_Key: params.owner_ref_key,
    Расширение: ext,
    Размер: String(bytes.length),
    ТипХраненияФайла: "ВИнформационнойБазе",
    ДатаСоздания: odataDate(now),
    ДатаМодификацииУниверсальная: odataDate(now),
    // Текст не извлекаем — это работа БСП на стороне 1С. Ставим честный
    // статус, чтобы поиск по содержимому не считал файл обработанным.
    СтатусИзвлеченияТекста: "НеИзвлечен",
    Описание: params.description ?? "",
  };
  if (author) {
    card.Автор_Key = author;
    card.Изменил_Key = author;
  }

  const file = (await oneCPost(
    buildODataPath(filesCatalog, { $format: "json" }),
    card,
  )) as { Ref_Key?: string };
  if (!file?.Ref_Key) throw new Error(`1С не вернула Ref_Key карточки файла (${filesCatalog})`);

  // 3. Связь карточки с данными. Без неё файл виден в списке, но не открывается.
  await oneCPost(
    buildODataPath("InformationRegister_ХранилищеФайлов", { $format: "json" }),
    {
      Файл: file.Ref_Key,
      Файл_Type: `StandardODATA.${filesCatalog}`,
      ХранилищеДвоичныхДанных_Key: storageKey,
    },
  );

  return JSON.stringify({
    ref_key: file.Ref_Key,
    files_catalog: filesCatalog,
    file_name: params.file_name,
    size: bytes.length,
    hash,
    storage_ref_key: storageKey,
    storage_reused: reused,
    storage_type: "ВИнформационнойБазе",
    note: "Текст файла не извлечён и в том не перенесён — это делает 1С штатными средствами.",
  });
}

// ──────────────────────────────────────────────────────────────
// list_attached_files
// ──────────────────────────────────────────────────────────────

export const listAttachedFilesSchema = z.object({
  owner_type: ownerTypeSchema,
  owner_ref_key: refKeySchema.describe("Ref_Key владельца"),
  top: z.number().int().min(1).max(200).default(50).describe("Сколько файлов вернуть"),
});

export async function handleListAttachedFiles(
  params: z.infer<typeof listAttachedFilesSchema>,
): Promise<string> {
  const filesCatalog = filesCatalogFor(params.owner_type);
  const result = (await oneCGet(
    buildODataPath(filesCatalog, {
      $filter: `ВладелецФайла_Key eq guid'${params.owner_ref_key}' and DeletionMark eq false`,
      // Содержимое и извлечённый текст не тянем: они весят мегабайты и в
      // списке не нужны — за содержимым есть get_attached_file.
      $select: "Ref_Key,Description,Расширение,Размер,ДатаСоздания,ТипХраненияФайла,ПутьКФайлу",
      $orderby: "ДатаСоздания desc",
      $top: String(params.top),
      $format: "json",
    }),
  )) as { value?: unknown[] };

  return JSON.stringify({ files: result?.value ?? [], files_catalog: filesCatalog });
}

// ──────────────────────────────────────────────────────────────
// get_attached_file
// ──────────────────────────────────────────────────────────────

export const getAttachedFileSchema = z.object({
  owner_type: ownerTypeSchema,
  ref_key: refKeySchema.describe("Ref_Key карточки файла"),
});

export async function handleGetAttachedFile(
  params: z.infer<typeof getAttachedFileSchema>,
): Promise<string> {
  const filesCatalog = filesCatalogFor(params.owner_type);
  const card = (await oneCGet(
    buildKeyedPath(filesCatalog, params.ref_key, undefined, {
      $select: "Ref_Key,Description,Расширение,Размер,ТипХраненияФайла,ПутьКФайлу",
      $format: "json",
    }),
  )) as Record<string, unknown>;

  // Файл в томе на диске сервера 1С — байты по OData недоступны в принципе.
  // Говорим это прямо, а не возвращаем пустое содержимое: пустой ответ
  // выглядел бы как «файл пустой».
  if (card?.ТипХраненияФайла === "ВТомахНаДиске") {
    return JSON.stringify({
      ...card,
      content_base64: null,
      error: "Файл хранится в томе на диске сервера 1С — через OData содержимое недоступно.",
    });
  }

  const link = (await oneCGet(
    buildODataPath("InformationRegister_ХранилищеФайлов", {
      $filter: `Файл eq cast(guid'${params.ref_key}', 'Catalog_${filesCatalog.replace(/^Catalog_/, "")}')`,
      $select: "ХранилищеДвоичныхДанных_Key",
      $top: "1",
      $format: "json",
    }),
  ).catch(() => null)) as { value?: Array<{ ХранилищеДвоичныхДанных_Key?: string }> } | null;

  const storageKey = link?.value?.[0]?.ХранилищеДвоичныхДанных_Key;
  if (!storageKey) {
    return JSON.stringify({ ...card, content_base64: null, error: "Не нашёл запись двоичных данных файла." });
  }

  const blob = (await oneCGet(
    buildKeyedPath("Catalog_ХранилищеДвоичныхДанных", storageKey, undefined, {
      $select: "ДвоичныеДанные_Base64Data,Хеш",
      $format: "json",
    }),
  )) as Record<string, unknown>;

  return JSON.stringify({
    ...card,
    hash: blob?.Хеш ?? null,
    content_base64: blob?.ДвоичныеДанные_Base64Data ?? null,
  });
}
