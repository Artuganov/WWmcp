import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { z } from "zod";
import { oneCGet, oneCPost, buildODataPath, buildKeyedPath, escapeODataString } from "../client.js";
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
 *    Так хранится большинство файлов этой базы. Через OData туда нельзя ни
 *    записать, ни прочитать: байтов в карточке нет вовсе. Читать их всё же
 *    можно, если том смонтирован к нам, — см. ONEC_FILE_VOLUMES ниже. Запись
 *    в том по-прежнему только средствами 1С.
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

/**
 * Тома файлов, смонтированные локально, — чтобы отдавать и те файлы, что
 * лежат не в базе, а на диске сервера 1С.
 *
 * Формат ONEC_FILE_VOLUMES: «путь_в_1С=путь_у_нас», через запятую. Путь в 1С
 * берётся из Catalog_ТомаХраненияФайлов.ПолныйПутьLinux как есть. Пример:
 *
 *   ONEC_FILE_VOLUMES=/mnt/1c-files/=/mnt/1c-files
 *
 * Если переменная не задана, поведение прежнее: по файлу из тома инструмент
 * честно отвечает, что содержимое недоступно. Это намеренно — сервер без
 * смонтированного тома не должен делать вид, что умеет больше, чем умеет.
 */
function volumeMounts(): Array<{ remote: string; local: string }> {
  const raw = process.env["ONEC_FILE_VOLUMES"]?.trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map((pair) => pair.trim())
    .filter(Boolean)
    .map((pair) => {
      const eq = pair.indexOf("=");
      if (eq < 1) throw new Error(`ONEC_FILE_VOLUMES: не понял «${pair}», нужно «путь_в_1С=путь_у_нас»`);
      return {
        remote: pair.slice(0, eq).trim().replace(/[/\\]+$/, ""),
        local: pair.slice(eq + 1).trim().replace(/[/\\]+$/, ""),
      };
    });
}

/**
 * Полный путь к файлу тома у нас на диске — или null, если том не смонтирован.
 *
 * Отдельно стережём выход за корень тома: ПутьКФайлу приходит из базы, а не
 * от пользователя, но «..» в нём превратили бы инструмент в чтение любого
 * файла на машине. Сравниваем уже после resolve, иначе «/mnt/1c-files-прочее»
 * прошло бы проверку на префикс.
 */
function resolveVolumePath(volumeRemoteRoot: string, relativePath: string): string | null {
  const wanted = volumeRemoteRoot.replace(/[/\\]+$/, "");
  const mount = volumeMounts().find((m) => m.remote === wanted);
  if (!mount) return null;

  const root = resolve(mount.local);
  const full = resolve(root, relativePath.replace(/\\/g, "/").replace(/^\/+/, ""));
  if (full !== root && !full.startsWith(root + sep)) {
    throw new Error(`Путь к файлу выводит за пределы тома: «${relativePath}»`);
  }
  return full;
}

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

/**
 * Отдаёт файл, лежащий в томе на диске сервера 1С.
 *
 * Том в карточке указан ссылкой, его путь живёт в Catalog_ТомаХраненияФайлов.
 * Берём путь оттуда, а не из переменной окружения в одиночку: томов может
 * быть несколько, и сопоставление «том из базы → наш каталог» должно быть
 * явным, иначе файл второго тома молча прочитался бы из первого.
 */
async function readFromVolume(card: Record<string, unknown>): Promise<string> {
  const unavailable = (error: string) => JSON.stringify({ ...card, content_base64: null, error });

  if (volumeMounts().length === 0) {
    return unavailable(
      "Файл хранится в томе на диске сервера 1С, а тома не смонтированы. " +
      "Чтобы читать такие файлы, смонтируйте том и укажите ONEC_FILE_VOLUMES.",
    );
  }

  const volumeKey = typeof card.Том_Key === "string" ? card.Том_Key : "";
  const relative = typeof card.ПутьКФайлу === "string" ? card.ПутьКФайлу : "";
  if (!volumeKey || !relative) {
    return unavailable("В карточке нет тома или пути к файлу — читать нечего.");
  }

  const volume = (await oneCGet(
    buildKeyedPath("Catalog_ТомаХраненияФайлов", volumeKey, undefined, {
      $select: "Description,ПолныйПутьLinux",
      $format: "json",
    }),
  ).catch(() => null)) as { Description?: string; ПолныйПутьLinux?: string } | null;

  const remoteRoot = volume?.ПолныйПутьLinux?.trim();
  if (!remoteRoot) {
    return unavailable(`Не нашёл путь тома ${volumeKey} в Catalog_ТомаХраненияФайлов.`);
  }

  let full: string | null;
  try {
    full = resolveVolumePath(remoteRoot, relative);
  } catch (e) {
    return unavailable(e instanceof Error ? e.message : String(e));
  }
  if (!full) {
    return unavailable(
      `Том «${volume?.Description ?? volumeKey}» (${remoteRoot}) у нас не смонтирован. ` +
      `Добавьте его в ONEC_FILE_VOLUMES как «${remoteRoot.replace(/\/+$/, "")}=<локальный путь>».`,
    );
  }

  // Размер берём с диска, а не из карточки: карточка может врать, если файл
  // подменили мимо 1С, а в память читаем именно то, что на диске.
  let size: number;
  try {
    size = (await stat(full)).size;
  } catch {
    return unavailable(`Файла нет на диске: ${full}. Том смонтирован не тот или файл удалён мимо 1С.`);
  }
  if (size > MAX_BYTES) {
    return unavailable(`Файл ${size} байт — больше предела ${MAX_BYTES}. Заберите его с диска напрямую.`);
  }

  let bytes: Buffer;
  try {
    bytes = await readFile(full);
  } catch (e) {
    return unavailable(
      `Не смог прочитать ${full}: ${e instanceof Error ? e.message : String(e)}. ` +
      "Обычно это права: том монтируется только на чтение, но под пользователем, которому файлы видны.",
    );
  }

  return JSON.stringify({
    ...card,
    storage: "volume",
    volume_name: volume?.Description ?? null,
    size_on_disk: size,
    hash: createHash("sha256").update(bytes).digest("base64"),
    content_base64: bytes.toString("base64"),
  });
}

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
      $select: "Ref_Key,Description,Расширение,Размер,ТипХраненияФайла,ПутьКФайлу,Том_Key",
      $format: "json",
    }),
  )) as Record<string, unknown>;

  // Файл в томе на диске сервера 1С. По OData байты недоступны в принципе,
  // поэтому читаем их с диска — если том смонтирован к нам (ONEC_FILE_VOLUMES).
  // Без монтирования отвечаем прямо, что содержимое недоступно: пустой ответ
  // выглядел бы как «файл пустой».
  if (card?.ТипХраненияФайла === "ВТомахНаДиске") {
    return await readFromVolume(card);
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

// ──────────────────────────────────────────────────────────────
// find_attached_files
// ──────────────────────────────────────────────────────────────

/**
 * Поиск файлов сразу по многим типам владельцев.
 *
 * Зачем отдельный инструмент. Единой таблицы «все присоединённые файлы» в 1С
 * нет: у каждого типа владельца свой справочник `<Владелец>ПрисоединенныеФайлы`,
 * в этой базе их около полутора сотен. Поэтому «все файлы по контрагенту» или
 * «все файлы за квартал» одним запросом не берутся — надо обойти каталоги.
 *
 * На диске это тем более не решается: том разложен по датам загрузки
 * (`20250411/имя.pdf`) и о контрагентах ничего не знает. Связь «файл → объект»
 * живёт только в карточке (ВладелецФайла_Key), то есть в базе.
 *
 * По умолчанию обходим не все каталоги, а коммерческий набор — те владельцы,
 * что реально привязаны к контрагенту. Полный обход полутора сотен каталогов
 * ради пары файлов стоит полторы сотни запросов; кому нужно — передаёт
 * owner_types явно.
 */
const COMMERCIAL_OWNER_TYPES = [
  "Catalog_ДоговорыКонтрагентов",
  "Catalog_Партнеры",
  "Catalog_СоглашенияСКлиентами",
  "Catalog_СоглашенияСПоставщиками",
  "Document_ЗаказКлиента",
  "Document_ЗаказПоставщику",
  "Document_РеализацияТоваровУслуг",
  "Document_ПриобретениеТоваровУслуг",
  "Document_СчетНаОплатуКлиенту",
  "Document_КоммерческоеПредложениеКлиенту",
  "Document_CRM_Интерес",
  "Document_АктВыполненныхРабот",
];

export const findAttachedFilesSchema = z.object({
  owner_types: z
    .array(z.string())
    .optional()
    .describe(
      "Типы владельцев для обхода. По умолчанию коммерческий набор: договоры, " +
      "партнёры, соглашения, заказы, реализации, приобретения, счета, КП, интересы, акты.",
    ),
  owner_ref: refKeySchema
    .optional()
    .describe("Ref_Key конкретного владельца — вернуть файлы только его"),
  created_from: z
    .string()
    .optional()
    .describe("Дата создания файла от, YYYY-MM-DD или YYYY-MM-DDTHH:MM:SS"),
  created_to: z.string().optional().describe("Дата создания файла до, включительно по датам"),
  name_contains: z.string().optional().describe("Подстрока в имени файла"),
  extension: z.string().optional().describe("Расширение без точки: pdf, docx"),
  top_per_catalog: z.number().int().min(1).max(1000).default(200)
    .describe("Сколько файлов брать максимум из одного каталога"),
});

/** «2026-07-01» → «2026-07-01T00:00:00»; с временем — как есть. */
function asODataDateTime(value: string, endOfDay = false): string {
  const v = value.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return `${v}T${endOfDay ? "23:59:59" : "00:00:00"}`;
  return v;
}

export async function handleFindAttachedFiles(
  params: z.infer<typeof findAttachedFilesSchema>,
): Promise<string> {
  const ownerTypes = params.owner_types?.length ? params.owner_types : COMMERCIAL_OWNER_TYPES;

  const conditions: string[] = [];
  if (params.owner_ref) conditions.push(`ВладелецФайла_Key eq guid'${params.owner_ref}'`);
  if (params.created_from)
    conditions.push(`ДатаСоздания ge datetime'${asODataDateTime(params.created_from)}'`);
  if (params.created_to)
    conditions.push(`ДатаСоздания le datetime'${asODataDateTime(params.created_to, true)}'`);
  if (params.extension)
    conditions.push(`Расширение eq '${escapeODataString(params.extension.replace(/^\./, ""))}'`);
  if (params.name_contains)
    conditions.push(`substringof('${escapeODataString(params.name_contains)}',Description)`);
  // Папки внутри каталога файлов — это группы, а не файлы.
  conditions.push("IsFolder eq false");
  const filter = conditions.join(" and ");

  // Каталог может не существовать (не у всякого владельца заведены файлы) или
  // не поддерживать отбор. Такой каталог пропускаем с пометкой, но не роняем
  // весь поиск: из-за одного отсутствующего владельца ответ стал бы пустым.
  const perCatalog = await Promise.all(
    ownerTypes.map(async (ownerType) => {
      let filesCatalog: string;
      try {
        filesCatalog = filesCatalogFor(ownerType);
      } catch (e) {
        return { ownerType, error: e instanceof Error ? e.message : String(e), files: [] };
      }
      try {
        const res = (await oneCGet(
          buildODataPath(filesCatalog, {
            $filter: filter,
            $select:
              "Ref_Key,Description,Расширение,Размер,ДатаСоздания,ТипХраненияФайла,ВладелецФайла_Key",
            $orderby: "ДатаСоздания desc",
            $top: String(params.top_per_catalog),
            $format: "json",
          }),
        )) as { value?: Array<Record<string, unknown>> };
        const files = (res?.value ?? []).map((f) => ({ ...f, owner_type: ownerType, files_catalog: filesCatalog }));
        return { ownerType, files };
      } catch (e) {
        return { ownerType, error: e instanceof Error ? e.message : String(e), files: [] };
      }
    }),
  );

  const files = perCatalog.flatMap((r) => r.files);
  const skipped = perCatalog
    .filter((r) => r.error)
    .map((r) => ({ owner_type: r.ownerType, error: r.error }));

  // Сводка по типам владельцев — чтобы было видно, где файлы вообще лежат,
  // не пролистывая весь список.
  const byOwnerType: Record<string, number> = {};
  for (const r of perCatalog) if (r.files.length) byOwnerType[r.ownerType] = r.files.length;

  return JSON.stringify({
    total: files.length,
    by_owner_type: byOwnerType,
    scanned_owner_types: ownerTypes.length,
    skipped: skipped.length ? skipped : undefined,
    filter,
    files,
  });
}
