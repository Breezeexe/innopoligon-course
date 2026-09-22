#!/usr/bin/env node

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs/promises";

const execFileAsync = promisify(execFile);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const exportRoot = path.resolve(process.env.EXPORT_DIR || path.join(scriptDir, ".."));
const sourceRoot = path.join(exportRoot, ".source", "api");

const token = process.env.INNOPOLIGON_TOKEN;
const baseUrl = (process.env.INNOPOLIGON_BASE_URL || "https://edu.innopoligon.ru").replace(/\/$/, "");
const proxy = process.env.INNOPOLIGON_PROXY || "socks5h://127.0.0.1:1080";
const userId = Number(process.env.INNOPOLIGON_USER_ID || 982);
const requestedCourseId = process.env.INNOPOLIGON_COURSE_ID
  ? Number(process.env.INNOPOLIGON_COURSE_ID)
  : 93;
const excludedTopicIds = new Set(
  (process.env.INNOPOLIGON_EXCLUDE_TOPIC_IDS || "314")
    .split(",")
    .map((value) => Number(value.trim()))
    .filter(Number.isFinite),
);

if (!token) {
  console.error("Set INNOPOLIGON_TOKEN before running this exporter.");
  process.exit(2);
}

const stats = {
  chapters: 0,
  topics: 0,
  theoryBlocks: 0,
  theoryFiles: 0,
  practiceCases: 0,
  assignments: 0,
  assignmentFiles: 0,
};

const transliteration = {
  а: "a", б: "b", в: "v", г: "g", д: "d", е: "e", ё: "e", ж: "zh",
  з: "z", и: "i", й: "i", к: "k", л: "l", м: "m", н: "n", о: "o",
  п: "p", р: "r", с: "s", т: "t", у: "u", ф: "f", х: "h", ц: "ts",
  ч: "ch", ш: "sh", щ: "sch", ъ: "", ы: "y", ь: "", э: "e", ю: "yu", я: "ya",
};

function slug(value, fallback = "item") {
  const text = String(value || "")
    .toLowerCase()
    .split("")
    .map((char) => transliteration[char] ?? char)
    .join("")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 100);
  return text || fallback;
}

function safeFilename(value, fallback = "file") {
  const parsed = path.parse(String(value || fallback));
  const ext = parsed.ext.toLowerCase().replace(/[^.a-z0-9]/g, "").slice(0, 12);
  return `${slug(parsed.name, fallback)}${ext}`;
}

function pad(value, width = 2) {
  return String(value).padStart(width, "0");
}

function sourceUrl(apiPath) {
  return `${baseUrl}${apiPath.startsWith("/") ? apiPath : `/${apiPath}`}`;
}

async function ensureDir(directory) {
  await fs.mkdir(directory, { recursive: true });
}

async function writeText(filename, content) {
  await ensureDir(path.dirname(filename));
  await fs.writeFile(filename, content.endsWith("\n") ? content : `${content}\n`, "utf8");
}

async function writeJson(filename, value) {
  await writeText(filename, JSON.stringify(value, null, 2));
}

async function curl(apiPath) {
  const url = apiPath.startsWith("http://") || apiPath.startsWith("https://")
    ? apiPath
    : sourceUrl(apiPath);
  const args = [
    "--silent",
    "--show-error",
    "--location",
    "--fail-with-body",
    "--retry", "3",
    "--retry-all-errors",
    "--retry-delay", "1",
    "--connect-timeout", "15",
    "--max-time", "120",
    "--proxy", proxy,
    "--header", "accept: application/json",
    "--header", `authorization: Bearer ${token}`,
    url,
  ];
  const { stdout } = await execFileAsync("curl", args, {
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
  });
  return stdout;
}

async function getJson(apiPath) {
  const body = await curl(apiPath);
  try {
    return JSON.parse(body.toString("utf8"));
  } catch (error) {
    throw new Error(`Invalid JSON from ${apiPath}: ${error.message}`);
  }
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  async function run() {
    while (true) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return results;
}

function orderedEntities(container, type, field) {
  const values = Array.isArray(container[field]) ? container[field] : [];
  const byId = new Map(values.map((value) => [String(value.uuid ?? value.id), value]));
  const ordered = [];
  const seen = new Set();
  for (const sequence of container.sequences || []) {
    if (sequence.type !== type) continue;
    const id = String(sequence.id);
    const value = byId.get(id);
    if (value) {
      ordered.push(value);
      seen.add(id);
    }
  }
  for (const value of values) {
    const id = String(value.uuid ?? value.id);
    if (!seen.has(id)) ordered.push(value);
  }
  return ordered;
}

function fileDescriptors(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => {
      if (typeof item === "string") return { id: item, label: item };
      if (!item || typeof item !== "object") return null;
      const id = item.id ?? item.file_id ?? item.uuid ?? item.name ?? item.file_name;
      if (!id) return null;
      return {
        id: String(id),
        label: String(item.original_id ?? item.original_name ?? item.file_name ?? item.name ?? id),
      };
    })
    .filter(Boolean);
}

async function downloadDescriptor(descriptor, destination, prefix = "") {
  const name = `${prefix}${safeFilename(descriptor.label, "attachment")}`;
  const target = path.join(destination, name);
  const data = await curl(`/api/teachings-files/${encodeURIComponent(descriptor.id)}`);
  await ensureDir(destination);
  await fs.writeFile(target, data);
  return { ...descriptor, name, target };
}

function renderAssignment(sql, noSql, downloadedFiles) {
  const lines = [
    `# ${sql.name || "Практическое задание"}`,
    "",
    `- UUID: \`${sql.uuid || noSql.assignment_uuid || ""}\``,
    `- Тип: \`${sql.task_type || "PRACTICE"}\``,
    `- Проходной результат: ${sql.min_percentage_correct_answers ?? "—"}%`,
    `- Максимум попыток: ${sql.attempt ?? "—"}`,
    `- Баллы: ${sql.score ?? "—"}`,
  ];

  if (sql.description) lines.push("", String(sql.description));
  if (noSql.legend) lines.push("", "## Описание", "", String(noSql.legend));

  const filesById = new Map(downloadedFiles.map((file) => [file.id, file]));
  const topFiles = fileDescriptors(noSql.files);
  if (topFiles.length) {
    lines.push("", "## Материалы", "");
    for (const file of topFiles) {
      const downloaded = filesById.get(file.id);
      lines.push(downloaded ? `- [${file.label}](assets/${downloaded.name})` : `- ${file.label}`);
    }
  }

  lines.push("", "## Вопросы", "");
  for (const [index, test] of (noSql.tests || []).entries()) {
    lines.push(`### ${index + 1}. ${test.quest || "Вопрос"}`, "");
    if (Array.isArray(test.variants)) {
      for (const variant of test.variants) lines.push(`- [ ] ${variant}`);
      lines.push("");
    } else {
      lines.push(`Тип ответа: \`${test.type || "INPUT"}\``, "");
    }
    if (Array.isArray(test.hints) && test.hints.length) {
      lines.push("Подсказки:", "");
      for (const hint of test.hints) {
        const text = typeof hint === "string" ? hint : hint.text ?? hint.hint ?? JSON.stringify(hint);
        lines.push(`- ${text}`);
      }
      lines.push("");
    }
    const questionFiles = fileDescriptors(test.files);
    if (questionFiles.length) {
      lines.push("Файлы:", "");
      for (const file of questionFiles) {
        const downloaded = filesById.get(file.id);
        lines.push(downloaded ? `- [${file.label}](assets/${downloaded.name})` : `- ${file.label}`);
      }
      lines.push("");
    }
  }
  return lines.join("\n").replace(/\n{3,}/g, "\n\n");
}

async function exportInfoBlocks(topic, topicDir) {
  const blocks = [
    ...orderedEntities(topic, "INFOBLOCK", "infoblocks").map((block) => ({ ...block, solved: false })),
    ...orderedEntities(topic, "INFOBLOCK_SOLVED", "infoblocks_solved").map((block) => ({ ...block, solved: true })),
  ];
  if (!blocks.length) return [];

  const theoryDir = path.join(topicDir, "theory");
  const assetsDir = path.join(theoryDir, "assets");
  await ensureDir(theoryDir);
  stats.theoryBlocks += blocks.length;

  const details = await mapLimit(blocks, 10, async (block, index) => {
    const endpoint = block.solved
      ? `/api/infoblock-solved/by-uuid/${encodeURIComponent(block.uuid)}?user_id=${userId}`
      : `/api/infoblock/by-uuid/${encodeURIComponent(block.uuid)}`;
    const detail = await getJson(endpoint);
    await writeJson(path.join(sourceRoot, "infoblocks", `${block.uuid}.json`), detail);
    return { block, detail, endpoint, index };
  });

  return mapLimit(details, 8, async ({ block, detail, endpoint, index }) => {
    const fileSequences = (detail.sequences || []).filter((sequence) => sequence.type === "TEACHINGS_FILES");
    const descriptors = fileSequences.map((sequence) => ({
      id: String(sequence.id),
      label: String(sequence.original_id || sequence.id),
    }));

    const downloaded = [];
    for (const [fileIndex, descriptor] of descriptors.entries()) {
      const ext = path.extname(descriptor.label).toLowerCase();
      const isMarkdown = ext === ".md" || ext === ".markdown";
      const prefix = descriptors.length > 1 ? `${pad(fileIndex + 1)}-` : "";
      const filename = isMarkdown
        ? `${pad(index + 1, 3)}-${slug(block.name)}${ext || ".md"}`
        : `${pad(index + 1, 3)}-${prefix}${safeFilename(descriptor.label)}`;
      const destination = isMarkdown ? theoryDir : assetsDir;
      const data = await curl(`/api/teachings-files/${encodeURIComponent(descriptor.id)}`);
      await ensureDir(destination);
      await fs.writeFile(path.join(destination, filename), data);
      downloaded.push({ ...descriptor, filename: isMarkdown ? filename : `assets/${filename}`, isMarkdown });
      stats.theoryFiles += 1;
    }

    if (!downloaded.length) {
      const filename = `${pad(index + 1, 3)}-${slug(block.name)}.md`;
      await writeText(
        path.join(theoryDir, filename),
        `# ${block.name || detail.name || "Материал"}\n\n${detail.description || block.description || ""}`,
      );
      downloaded.push({ filename, isMarkdown: true, generated: true });
    }

    return {
      order: index + 1,
      name: block.name || detail.name,
      uuid: block.uuid,
      source: sourceUrl(endpoint),
      files: downloaded,
    };
  });
}

async function exportCases(topic, topicDir) {
  const cases = orderedEntities(topic, "CASE_CONTAINER", "case_containers");
  if (!cases.length) return [];
  const practiceDir = path.join(topicDir, "practice");
  await ensureDir(practiceDir);
  stats.practiceCases += cases.length;

  return mapLimit(cases, 6, async (caseMeta, caseIndex) => {
    const caseEndpoint = `/api/case-container/id/${caseMeta.id}?user_id=${userId}`;
    const caseDetail = await getJson(caseEndpoint);
    await writeJson(path.join(sourceRoot, "cases", `${caseMeta.id}.json`), caseDetail);

    const assignments = orderedEntities(caseDetail, "ASSIGNMENT", "assignments");
    const renderedAssignments = await mapLimit(assignments, 4, async (assignment, assignmentIndex) => {
      const uuid = assignment.uuid;
      const sqlEndpoint = `/api/assignment/sql-part/${encodeURIComponent(uuid)}?user_id=${userId}`;
      const noSqlEndpoint = `/api/assignment/nosql-part/${encodeURIComponent(uuid)}?user_id=${userId}`;
      const [sql, noSql] = await Promise.all([getJson(sqlEndpoint), getJson(noSqlEndpoint)]);
      await Promise.all([
        writeJson(path.join(sourceRoot, "assignments", `${uuid}-sql.json`), sql),
        writeJson(path.join(sourceRoot, "assignments", `${uuid}-nosql.json`), noSql),
      ]);

      const allDescriptors = [
        ...fileDescriptors(noSql.files),
        ...(noSql.tests || []).flatMap((test) => fileDescriptors(test.files)),
      ];
      const uniqueDescriptors = [...new Map(allDescriptors.map((file) => [file.id, file])).values()];
      const assignmentStem = `${pad(caseIndex + 1, 2)}-${slug(caseMeta.name)}`;
      const assignmentDir = path.join(practiceDir, assignmentStem);
      const assetsDir = path.join(assignmentDir, "assets");
      const downloadedFiles = await mapLimit(uniqueDescriptors, 5, async (descriptor, index) => {
        stats.assignmentFiles += 1;
        return downloadDescriptor(descriptor, assetsDir, `${pad(index + 1, 2)}-`);
      });
      const filename = assignments.length > 1
        ? `${pad(assignmentIndex + 1, 2)}-${slug(sql.name)}.md`
        : "README.md";
      await writeText(path.join(assignmentDir, filename), renderAssignment(sql, noSql, downloadedFiles));
      stats.assignments += 1;
      return {
        name: sql.name,
        uuid,
        file: `${assignmentStem}/${filename}`,
        source: sourceUrl(noSqlEndpoint),
      };
    });

    return {
      order: caseIndex + 1,
      id: caseMeta.id,
      name: caseMeta.name,
      source: sourceUrl(caseEndpoint),
      assignments: renderedAssignments,
    };
  });
}

function renderTopicIndex(chapter, childTopics, theoryEntries, caseEntries) {
  const lines = [
    `# ${chapter.name}`,
    "",
    chapter.description || "",
    "",
  ];
  if (theoryEntries.length) {
    lines.push("## Теория", "");
    for (const entry of theoryEntries) {
      const mainFile = entry.files.find((file) => file.isMarkdown) || entry.files[0];
      lines.push(`${entry.order}. [${entry.name}](theory/${mainFile.filename})`);
    }
    lines.push("");
  }
  if (caseEntries.length) {
    lines.push("## Практика", "");
    for (const item of caseEntries) {
      for (const assignment of item.assignments) {
        lines.push(`${item.order}. [${assignment.name}](practice/${assignment.file})`);
      }
    }
    lines.push("");
  }
  lines.push("## Исходные страницы", "");
  for (const topic of childTopics) {
    lines.push(`- [${topic.name}](${baseUrl}/course/${requestedCourseId}/topic/${topic.id})`);
  }
  return lines.join("\n");
}

async function main() {
  await ensureDir(sourceRoot);
  const courseEndpoint = `/api/course/with-included-entities-by-user-id/${userId}`;
  const courses = await getJson(courseEndpoint);
  if (!Array.isArray(courses) || courses.length === 0) throw new Error("No courses returned by the API.");
  const course = courses.find((item) => item.id === requestedCourseId) || courses[0];
  await writeJson(path.join(sourceRoot, "courses.json"), courses);

  const topById = new Map((course.topics || []).map((topic) => [String(topic.id), topic]));
  const chapterMetas = (course.sequences || [])
    .filter((sequence) => sequence.type === "TOPIC")
    .map((sequence) => topById.get(String(sequence.id)))
    .filter(Boolean)
    .filter((topic) => !excludedTopicIds.has(Number(topic.id)));

  console.log(`Course: ${course.name}`);
  console.log(`Chapters selected: ${chapterMetas.length}; excluded topic IDs: ${[...excludedTopicIds].join(", ")}`);

  const chapterDetails = await mapLimit(chapterMetas, 8, async (chapter) => {
    const endpoint = `/api/topic/topic-with-included-entities/${chapter.id}?user_id=${userId}`;
    const detail = await getJson(endpoint);
    await writeJson(path.join(sourceRoot, "topics", `${chapter.id}.json`), detail);
    return detail;
  });

  const rootLinks = [];
  for (const [chapterIndex, chapter] of chapterDetails.entries()) {
    const chapterName = `${pad(chapterIndex + 1)}-${slug(chapter.name)}`;
    const chapterDir = path.join(exportRoot, chapterName);
    const children = orderedEntities(chapter, "TOPIC", "topics");
    const childDetails = await mapLimit(children, 6, async (child) => {
      const endpoint = `/api/topic/topic-with-included-entities/${child.id}?user_id=${userId}`;
      const detail = await getJson(endpoint);
      await writeJson(path.join(sourceRoot, "topics", `${child.id}.json`), detail);
      return detail;
    });

    const theoryEntries = [];
    const caseEntries = [];
    for (const child of childDetails) {
      theoryEntries.push(...await exportInfoBlocks(child, chapterDir));
      caseEntries.push(...await exportCases(child, chapterDir));
    }

    await writeText(
      path.join(chapterDir, "README.md"),
      renderTopicIndex(chapter, childDetails, theoryEntries, caseEntries),
    );
    rootLinks.push({
      name: chapter.name,
      directory: chapterName,
      theoryCount: theoryEntries.length,
      practiceCount: caseEntries.length,
    });
    stats.chapters += 1;
    stats.topics += childDetails.length;
    console.log(
      `[${chapterIndex + 1}/${chapterDetails.length}] ${chapter.name}: ` +
      `${theoryEntries.length} theory blocks, ${caseEntries.length} practice cases`,
    );
  }

  const exportedAt = new Date().toISOString();
  const readme = [
    `# ${course.name}`,
    "",
    `Архив учебного курса с платформы [edu.innopoligon.ru](${baseUrl}). Материалы сохранены в Markdown с исходной структурой, таблицами, блоками кода и ссылками на источники. Практические задания вынесены в отдельные каталоги рядом с соответствующей теорией.`,
    "",
    course.description_full || "",
    "",
    "## Что находится в репозитории",
    "",
    `- ${stats.chapters} тематических разделов;`,
    `- ${stats.theoryBlocks} теоретических конспекта в исходном Markdown;`,
    `- ${stats.assignments} практических задания;`,
    "- ссылки на источники в теоретических материалах;",
    "- исходные ответы API для проверки полноты экспорта;",
    "- скрипт для повторной выгрузки материалов;",
    "- файл контрольных сумм SHA-256.",
    "",
    "Финальный экзамен намеренно исключён из архива.",
    "",
    "## Оглавление",
    "",
    "| № | Раздел | Теория | Практика |",
    "|---:|---|---:|---:|",
    ...rootLinks.map((item, index) =>
      `| ${index + 1} | [${item.name}](${item.directory}/README.md) | ${item.theoryCount} | ${item.practiceCount} |`,
    ),
    `|  | **Всего** | **${stats.theoryBlocks}** | **${stats.assignments}** |`,
    "",
    "README каждого раздела содержит полное оглавление со ссылками на отдельные конспекты и практические задания.",
    "",
    "## Структура архива",
    "",
    "```text",
    "innopoligon-export/",
    "├── 01-.../ — разделы курса",
    "│   ├── README.md — оглавление раздела",
    "│   ├── theory/ — оригинальные Markdown-конспекты",
    "│   └── practice/ — практические задания",
    "├── .source/api/ — исходные JSON-ответы API",
    "├── tools/export.mjs — скрипт повторного экспорта",
    "├── manifest.json — состав и параметры выгрузки",
    "├── EXPORT_REPORT.md — результаты проверки полноты",
    "└── SHA256SUMS — контрольные суммы файлов",
    "```",
    "",
    "Для чтения откройте нужный раздел в таблице выше, затем выберите материал в его оглавлении. Теория хранится без преобразования текста. В практических заданиях сохранены вопросы, варианты ответа, метаданные и доступные вложения; ответы не запрашивались и не генерировались.",
    "",
    "## Проверка экспорта",
    "",
    `Материалы экспортированы ${exportedAt}. Сводная статистика находится в [manifest.json](manifest.json), результаты проверки и известные отсутствующие иллюстрации — в [EXPORT_REPORT.md](EXPORT_REPORT.md).`,
    "",
    "Проверить целостность файлов можно командой:",
    "",
    "```bash",
    "sha256sum -c SHA256SUMS",
    "```",
    "",
    "Bearer-токен и другие данные авторизации в репозиторий не сохраняются.",
    "",
    "## Повторная выгрузка",
    "",
    "Для работы скрипта на VPS должен быть доступен обратный SOCKS-прокси на `127.0.0.1:1080`. Токен передаётся только через переменную окружения:",
    "",
    "```bash",
    "read -rsp \"Bearer token: \" INNOPOLIGON_TOKEN",
    "export INNOPOLIGON_TOKEN",
    "node tools/export.mjs",
    "unset INNOPOLIGON_TOKEN",
    "```",
    "",
    `По умолчанию скрипт выгружает курс \`${course.id}\` для пользователя \`${userId}\` и исключает темы \`${[...excludedTopicIds].join(",")}\`. Эти значения можно изменить переменными \`INNOPOLIGON_COURSE_ID\`, \`INNOPOLIGON_USER_ID\` и \`INNOPOLIGON_EXCLUDE_TOPIC_IDS\`.`,
  ].join("\n");
  await writeText(path.join(exportRoot, "README.md"), readme);
  await writeText(path.join(exportRoot, ".gitignore"), ".env\n*.token\n.cache/\n");
  await writeJson(path.join(exportRoot, "manifest.json"), {
    source: baseUrl,
    exported_at: exportedAt,
    user_id: userId,
    course_id: course.id,
    course_name: course.name,
    excluded_topic_ids: [...excludedTopicIds],
    stats,
  });

  console.log("Export complete:", exportRoot);
  console.log(JSON.stringify(stats));
}

main().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exit(1);
});
