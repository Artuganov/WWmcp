/**
 * Присоединённые файлы: вывод имени каталога и разбор имени файла.
 *
 * Имена каталогов проверены по живой базе (UT «Хроники»): такие сущности там
 * действительно есть — Catalog_ЗаказПоставщикуПрисоединенныеФайлы,
 * Catalog_ЗаказКлиентаПрисоединенныеФайлы, Catalog_ПартнерыПрисоединенныеФайлы.
 * Правило вывода — единственное, что стоит между владельцем и записью файла:
 * ошибись в нём, и файл уедет в несуществующий справочник.
 */
import { describe, it, expect } from "vitest";
import { filesCatalogFor, splitFileName } from "../src/tools/files.js";

describe("filesCatalogFor", () => {
  it("снимает префикс типа и добавляет суффикс", () => {
    expect(filesCatalogFor("Document_ЗаказПоставщику")).toBe("Catalog_ЗаказПоставщикуПрисоединенныеФайлы");
    expect(filesCatalogFor("Document_ЗаказКлиента")).toBe("Catalog_ЗаказКлиентаПрисоединенныеФайлы");
    expect(filesCatalogFor("Catalog_Партнеры")).toBe("Catalog_ПартнерыПрисоединенныеФайлы");
  });

  it("принимает имя и без префикса", () => {
    expect(filesCatalogFor("ЗаказПоставщику")).toBe("Catalog_ЗаказПоставщикуПрисоединенныеФайлы");
  });

  it("не путает префикс с началом имени", () => {
    // «Документы» начинается на «Document», но префиксом не является:
    // срезать его значило бы уехать в Catalog_ыПрисоединенныеФайлы.
    expect(filesCatalogFor("Catalog_Документы")).toBe("Catalog_ДокументыПрисоединенныеФайлы");
  });

  it("пустой тип владельца — понятная ошибка, а не кривое имя", () => {
    expect(() => filesCatalogFor("Document_")).toThrow();
    expect(() => filesCatalogFor("   ")).toThrow();
  });
});

describe("splitFileName", () => {
  it("делит имя и расширение — 1С хранит их порознь", () => {
    expect(splitFileName("QH-Lab3.docx")).toEqual({ base: "QH-Lab3", ext: "docx" });
    expect(splitFileName("Счёт 2026-01.PDF")).toEqual({ base: "Счёт 2026-01", ext: "pdf" });
  });

  it("имя с точками внутри режет по последней", () => {
    expect(splitFileName("acme.invoice.v2.xlsx")).toEqual({ base: "acme.invoice.v2", ext: "xlsx" });
  });

  it("без расширения и с точкой на краю расширение пустое", () => {
    expect(splitFileName("README")).toEqual({ base: "README", ext: "" });
    expect(splitFileName(".gitignore")).toEqual({ base: ".gitignore", ext: "" });
    expect(splitFileName("archive.")).toEqual({ base: "archive.", ext: "" });
  });

  it("разделители пути вычищает — имя файла не должно уводить в каталог", () => {
    expect(splitFileName("../../etc/passwd.txt")).toEqual({ base: ".._.._etc_passwd", ext: "txt" });
  });
});
