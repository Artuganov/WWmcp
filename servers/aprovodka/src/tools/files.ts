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
  folder: z.string().optional().describe(
    "Имя папки в карточке файлов владельца, например «Черновик». Папка должна уже существовать.",
  ),
  folder_ref_key: refKeySchema.optional().describe(
    "Ref_Key папки — когда известен точно; тогда folder не нужен.",
  ),
});

/**
 * Найти папку в карточке присоединённых файлов владельца.
 *
 * Папки — элементы того же справочника с IsFolder = true, и у каждой свой
 * ВладелецФайла. Поэтому ищем по владельцу И по имени: «Черновик» у одного
 * договора и «Черновик» у другого — разные папки, и подставить чужую нельзя.
 */
async function resolveFileFolder(
  filesCatalog: string,
  ownerRefKey: string,
  name: string,
): Promise<string> {
  const escaped = name.replace(/'/g, "''");
  const res = (await oneCGet(
    buildODataPath(filesCatalog, {
      $filter: `IsFolder eq true and ВладелецФайла_Key eq guid'${ownerRefKey}' and Description eq '${escaped}'`,
      $select: "Ref_Key,Description",
      $top: "2",
      $format: "json",
    }),
  )) as { value?: Array<{ Ref_Key?: string }> };

  const found = res?.value ?? [];
  if (found.length === 1 && found[0].Ref_Key) return found[0].Ref_Key;
  if (found.length > 1) {
    throw new Error(`У этого владельца несколько папок «${name}» — передайте folder_ref_key`);
  }

  // Не нашли — перечислим, что есть. Иначе человек гадает, как папка названа
  // на самом деле, и пробует варианты вслепую.
  const all = (await oneCGet(
    buildODataPath(filesCatalog, {
      $filter: `IsFolder eq true and ВладелецФайла_Key eq guid'${ownerRefKey}'`,
      $select: "Description",
      $top: "50",
      $format: "json",
    }),
  )) as { value?: Array<{ Description?: string }> };
  const names = (all?.value ?? []).map((f) => f.Description).filter(Boolean);
  throw new Error(
    `Папка «${name}» у этого владельца не найдена.` +
      (names.length
        ? ` Есть такие: ${names.join(", ")}.`
        : " Папок у него нет вообще — создайте её в 1С."),
  );
}

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

  // Папка. Без неё файл ляжет в корень карточки, и его придётся переносить
  // руками — отдельным запросом, которого у вызывающего может и не быть.
  let folderKey: string | null = params.folder_ref_key ?? null;
  if (!folderKey && params.folder) {
    folderKey = await resolveFileFolder(filesCatalog, params.owner_ref_key, params.folder);
  }
  if (folderKey) card.Parent_Key = folderKey;

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
    folder_ref_key: folderKey,
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
  compact: z.boolean().optional().describe(
    "Компактная выдача: короткие ключи и владельцы отдельной картой, без повтора " +
    "блока владельца в каждом файле. Нужна тому, кто читает сотни файлов разом: " +
    "обычный ответ упирается в предел 50 000 символов и приезжает обрезанным.",
  ),
  top_per_catalog: z.number().int().min(1).max(1000).default(200)
    .describe("Сколько файлов брать максимум из одного каталога"),
  resolve_owner: z
    .boolean()
    .default(false)
    .describe(
      "Дочитать владельца каждого файла и вытащить из него контрагента, партнёра и " +
      "представление. Нужно, чтобы разложить выгрузку по контрагентам: в карточке файла " +
      "есть только ссылка на документ. Стоит по запросу на каждого уникального владельца.",
    ),
  counterparty_ref: refKeySchema
    .optional()
    .describe("Оставить только файлы, чей владелец привязан к этому контрагенту. Включает resolve_owner."),
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
    ownerTypes.map(async (ownerType): Promise<{ ownerType: string; error?: string; files: Array<Record<string, unknown>> }> => {
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
              "Ref_Key,Description,Расширение,Размер,ДатаСоздания,ТипХраненияФайла," +
              "ВладелецФайла_Key,ПутьКФайлу,Том_Key",
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

  let files = perCatalog.flatMap((r) => r.files);
  const skipped = perCatalog
    .filter((r) => r.error)
    .map((r) => ({ owner_type: r.ownerType, error: r.error }));

  // Путь файла в томе. Отдаём его всегда, когда можем: вытащить сотню файлов
  // через base64 в ответе инструмента нереально — «все файлы за квартал» это
  // десятки мегабайт, которые пришлось бы прогнать через контекст модели.
  // Зная путь, байты забирают с диска напрямую там, где том смонтирован.
  const volumePaths = await volumePathIndex(files);
  files = files.map((f) => {
    const vol = typeof f.Том_Key === "string" ? volumePaths.get(f.Том_Key) : undefined;
    const rel = typeof f.ПутьКФайлу === "string" ? f.ПутьКФайлу.replace(/\\/g, "/") : "";
    return vol && rel
      ? { ...f, volume_path: vol.replace(/\/+$/, "") + "/" + rel.replace(/^\/+/, "") }
      : f;
  });

  // Разрешение владельца до контрагента. В карточке файла его нет — только
  // ссылка на документ, поэтому документ приходится дочитывать.
  const needOwners = params.resolve_owner || Boolean(params.counterparty_ref);
  if (needOwners) {
    const owners = await resolveOwners(files);
    files = files.map((f) => {
      const key = `${f.owner_type}|${f.ВладелецФайла_Key}`;
      const o = owners.get(key);
      return o ? { ...f, owner: o } : f;
    });
    if (params.counterparty_ref) {
      const want = params.counterparty_ref.toLowerCase();
      files = files.filter(
        (f) =>
          (f.owner as { counterparty_key?: string } | undefined)?.counterparty_key?.toLowerCase() === want,
      );
    }
  }

  // Сводка по типам владельцев — чтобы было видно, где файлы вообще лежат,
  // не пролистывая весь список.
  const byOwnerType: Record<string, number> = {};
  for (const f of files) {
    const t = String(f.owner_type);
    byOwnerType[t] = (byOwnerType[t] ?? 0) + 1;
  }

  // Разбивка по контрагентам — то, ради чего обычно и зовут resolve_owner.
  let byCounterparty: Record<string, number> | undefined;
  if (needOwners) {
    byCounterparty = {};
    for (const f of files) {
      const o = f.owner as { counterparty_name?: string } | undefined;
      const name = o?.counterparty_name || "(контрагент не определён)";
      byCounterparty[name] = (byCounterparty[name] ?? 0) + 1;
    }
  }

  // Компактная выдача. Обычная повторяет блок владельца в каждом файле, и на
  // сотне файлов ответ упирается в предел инструмента (50 000 символов) —
  // JSON приезжает обрезанным, и вызывающему приходится дробить запрос на
  // десятки частей. Здесь владельцы вынесены в отдельную карту, а ключи
  // укорочены: та же выдача занимает втрое меньше.
  if (params.compact) {
    const owners: Record<string, { p?: unknown; num?: unknown; dt?: unknown; cp?: unknown }> = {};
    const slim = files.map((f) => {
      const key = `${f.owner_type}|${f.ВладелецФайла_Key}`;
      const o = f.owner as Record<string, unknown> | undefined;
      if (o && !owners[key]) {
        owners[key] = { p: o.presentation, num: o.number, dt: o.date, cp: o.counterparty_name };
      }
      return {
        k: f.Ref_Key,
        n: f.Description,
        e: f.Расширение,
        s: f.Размер,
        d: f.ДатаСоздания,
        t: f.owner_type,
        o: f.ВладелецФайла_Key,
      };
    });

    return JSON.stringify({
      total: files.length,
      by_owner_type: byOwnerType,
      scanned_owner_types: ownerTypes.length,
      skipped: skipped.length ? skipped : undefined,
      compact: true,
      owners,
      files: slim,
    });
  }

  return JSON.stringify({
    total: files.length,
    by_owner_type: byOwnerType,
    by_counterparty: byCounterparty,
    scanned_owner_types: ownerTypes.length,
    skipped: skipped.length ? skipped : undefined,
    filter,
    files,
  });
}

/**
 * Пути томов по их ссылкам — одним запросом на весь результат поиска.
 *
 * По строке на файл это был бы запрос на каждый файл ради одного и того же
 * пути: том в базе обычно один.
 */
async function volumePathIndex(
  files: Array<Record<string, unknown>>,
): Promise<Map<string, string>> {
  const index = new Map<string, string>();
  const keys = [...new Set(files.map((f) => f.Том_Key).filter((k): k is string => typeof k === "string" && !/^0{8}-/.test(k)))];
  if (keys.length === 0) return index;

  const res = (await oneCGet(
    buildODataPath("Catalog_ТомаХраненияФайлов", {
      $select: "Ref_Key,ПолныйПутьLinux",
      $format: "json",
    }),
  ).catch(() => null)) as { value?: Array<{ Ref_Key?: string; ПолныйПутьLinux?: string }> } | null;

  for (const v of res?.value ?? []) {
    if (v.Ref_Key && v.ПолныйПутьLinux) index.set(v.Ref_Key, v.ПолныйПутьLinux);
  }
  return index;
}

/**
 * Владельцы файлов: представление документа и привязка к контрагенту.
 *
 * Поле с контрагентом у разных типов владельцев называется по-разному, а у
 * части (например, у самого партнёра) его нет вовсе — он и есть владелец.
 * Поэтому не угадываем по типу, а читаем запись целиком и смотрим, какие из
 * известных полей в ней есть. Дороже по трафику, зато работает на любом типе,
 * включая те, что появятся позже.
 *
 * Запрос идёт на каждого уникального владельца, а не на каждый файл: к одному
 * договору обычно подшито несколько файлов.
 */
async function resolveOwners(
  files: Array<Record<string, unknown>>,
): Promise<Map<string, Record<string, unknown>>> {
  const resolved = new Map<string, Record<string, unknown>>();

  const unique = new Map<string, { ownerType: string; ref: string }>();
  for (const f of files) {
    const ownerType = typeof f.owner_type === "string" ? f.owner_type : "";
    const ref = typeof f.ВладелецФайла_Key === "string" ? f.ВладелецФайла_Key : "";
    if (!ownerType || !ref || /^0{8}-/.test(ref)) continue;
    unique.set(`${ownerType}|${ref}`, { ownerType, ref });
  }

  const counterpartyNames = new Map<string, string>();

  await Promise.all(
    [...unique.entries()].map(async ([key, { ownerType, ref }]) => {
      const rec = (await oneCGet(
        buildKeyedPath(ownerType, ref, undefined, { $format: "json" }),
      ).catch(() => null)) as Record<string, unknown> | null;
      if (!rec) return;

      // Контрагент бывает прямым полем, бывает владельцем (у договора —
      // Владелец), а у самого контрагента его нет: он и есть владелец.
      const cpKey =
        (typeof rec.Контрагент_Key === "string" && rec.Контрагент_Key) ||
        (ownerType === "Catalog_Контрагенты" ? ref : "") ||
        "";
      const partnerKey = typeof rec.Партнер_Key === "string" ? rec.Партнер_Key : "";

      resolved.set(key, {
        owner_type: ownerType,
        ref_key: ref,
        presentation: rec.Description ?? rec.Номер ?? null,
        number: rec.Номер ?? null,
        date: rec.Date ?? rec.Дата ?? null,
        counterparty_key: cpKey || null,
        partner_key: partnerKey || null,
      });
      if (cpKey && !/^0{8}-/.test(cpKey)) counterpartyNames.set(cpKey, "");
    }),
  );

  // Имена контрагентов — одним запросом на всех, а не по одному на файл.
  if (counterpartyNames.size) {
    const res = (await oneCGet(
      buildODataPath("Catalog_Контрагенты", {
        $select: "Ref_Key,Description,ИНН",
        $top: "1000",
        $format: "json",
      }),
    ).catch(() => null)) as { value?: Array<{ Ref_Key?: string; Description?: string; ИНН?: string }> } | null;
    for (const c of res?.value ?? []) {
      if (c.Ref_Key && counterpartyNames.has(c.Ref_Key)) counterpartyNames.set(c.Ref_Key, c.Description ?? "");
    }
    for (const [, owner] of resolved) {
      const k = owner.counterparty_key;
      if (typeof k === "string" && counterpartyNames.has(k)) {
        owner.counterparty_name = counterpartyNames.get(k) || null;
      }
    }
  }

  return resolved;
}

// ──────────────────────────────────────────────────────────────
// export_attached_files
// ──────────────────────────────────────────────────────────────

/**
 * Выгрузка файлов ссылками.
 *
 * Зачем отдельно от get_attached_file. Ответ любого инструмента обрезается на
 * 50 000 символов (mcp-core/sanitize) — это ~37 КБ исходного файла. Договор на
 * 3,6 МБ через base64 не пройдёт в принципе, и даже если бы прошёл, он занял
 * бы ~4,9 МБ контекста модели. Поэтому байты здесь вообще не возвращаются:
 * файл уезжает на бэкенд, а наружу идёт ссылка со сроком жизни в час.
 *
 * Так это работает из любой сессии, у которой есть MCP, — ssh и доступ к
 * серверам не нужны.
 *
 * Требует EXPORT_UPLOAD_TOKEN; без него инструмент честно говорит, что не
 * настроен, вместо попытки залить файл в никуда.
 */
const UPLOAD_URL = process.env["EXPORT_UPLOAD_URL"]?.trim() || "https://parts.mrkt.ru/api/temp-downloads";

export const exportAttachedFilesSchema = z.object({
  owner_type: ownerTypeSchema,
  ref_keys: z
    .array(refKeySchema)
    .min(1)
    .max(50)
    .describe("Ref_Key карточек файлов (из find_attached_files или list_attached_files)"),
  note: z
    .string()
    .optional()
    .describe("Пояснение, которое сохранится рядом со ссылкой: контрагент, договор, интерес"),
  archive: z
    .boolean()
    .optional()
    .describe(
      "Сложить всё в один архив и вернуть одну ссылку. По умолчанию архив собирается " +
      "сам, когда файлов больше десяти: полсотни ссылок в ответе не переслать и не скачать.",
    ),
  archive_name: z.string().optional().describe("Имя архива, например «Договоры Нутриция»"),
});

/** От скольких файлов собираем архив, если не сказано иначе. */
const ARCHIVE_FROM = 10;

/** Байты файла — из тома или из базы, смотря где он лежит. */
async function fileBytes(
  ownerType: string,
  refKey: string,
): Promise<{ bytes: Buffer; name: string } | { error: string }> {
  const raw = await handleGetAttachedFile({ owner_type: ownerType, ref_key: refKey });
  const card = JSON.parse(raw) as Record<string, unknown>;

  const base = typeof card.Description === "string" ? card.Description : refKey;
  const ext = typeof card.Расширение === "string" && card.Расширение ? "." + card.Расширение : "";
  const name = base.endsWith(ext) ? base : base + ext;

  if (typeof card.content_base64 !== "string" || !card.content_base64) {
    return { error: typeof card.error === "string" ? card.error : "Содержимое файла недоступно" };
  }
  return { bytes: Buffer.from(card.content_base64, "base64"), name };
}

export async function handleExportAttachedFiles(
  params: z.infer<typeof exportAttachedFilesSchema>,
): Promise<string> {
  const token = process.env["EXPORT_UPLOAD_TOKEN"]?.trim();
  if (!token) {
    return JSON.stringify({
      error:
        "Выгрузка ссылками не настроена: нет EXPORT_UPLOAD_TOKEN. " +
        "Задайте его в окружении сервера, он должен совпадать с TEMP_DOWNLOAD_TOKEN на бэкенде.",
    });
  }

  const results: Array<Record<string, unknown>> = [];

  // Последовательно, а не пачкой: файлы тяжёлые, и десяток параллельных
  // загрузок по несколько мегабайт — это лишняя нагрузка и на том, и на бэкенд.
  for (const refKey of params.ref_keys) {
    const got = await fileBytes(params.owner_type, refKey);
    if ("error" in got) {
      results.push({ ref_key: refKey, error: got.error });
      continue;
    }

    try {
      const res = await fetch(UPLOAD_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Export-Token": token },
        body: JSON.stringify({
          name: got.name,
          content_base64: got.bytes.toString("base64"),
          source: "1c",
          note: params.note ?? "",
        }),
      });

      const text = await res.text();
      if (!res.ok) {
        results.push({ ref_key: refKey, name: got.name, error: `Бэкенд ответил ${res.status}: ${text.slice(0, 200)}` });
        continue;
      }

      const body = JSON.parse(text) as Record<string, unknown>;
      results.push({
        ref_key: refKey,
        name: got.name,
        size: got.bytes.length,
        url: body.url ?? null,
        expires_at: body.expires_at ?? null,
      });
    } catch (e) {
      results.push({ ref_key: refKey, name: got.name, error: e instanceof Error ? e.message : String(e) });
    }
  }

  const ok = results.filter((r) => r.url).length;
  const wantArchive = params.archive ?? ok > ARCHIVE_FROM;

  if (wantArchive && ok > 1) {
    const tokens = results
      .map((r) => (typeof r.url === "string" ? r.url.split("/").pop() : null))
      .filter((t): t is string => Boolean(t));

    try {
      const res = await fetch(UPLOAD_URL.replace(/\/+$/, "") + "/archive", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Export-Token": token },
        body: JSON.stringify({
          tokens,
          name: params.archive_name ?? "",
          note: params.note ?? "",
        }),
      });
      const text = await res.text();
      if (res.ok) {
        const body = JSON.parse(text) as Record<string, unknown>;
        return JSON.stringify({
          archive: true,
          total: results.length,
          uploaded: ok,
          failed: results.length - ok,
          url: body.url ?? null,
          name: body.name ?? null,
          size: body.size ?? null,
          files_in_archive: body.files_in_archive ?? null,
          expires_at: body.expires_at ?? null,
          hint: "Ссылка живёт час. Отдавать пользователю целиком, вместе с https://.",
          // Что не попало в архив — показываем отдельно, иначе пользователь
          // решит, что выгрузилось всё.
          skipped: results.filter((r) => r.error),
        });
      }
      // Архив не собрался — отдаём отдельные ссылки, они уже рабочие.
      // Молчать тут нельзя: иначе непонятно, почему ссылок много.
      results.push({ archive_error: `Архив собрать не удалось (${res.status}): ${text.slice(0, 200)}` });
    } catch (e) {
      results.push({ archive_error: e instanceof Error ? e.message : String(e) });
    }
  }

  return JSON.stringify({
    archive: false,
    total: results.length,
    uploaded: ok,
    failed: results.length - ok,
    hint: "Ссылки живут час. Отдавать пользователю целиком, вместе с https://.",
    files: results,
  });
}
