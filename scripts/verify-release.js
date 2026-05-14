const fs = require("fs");

const index = fs.readFileSync("index.html", "utf8");
const server = fs.readFileSync("server.js", "utf8");

const checks = [
  ["index.html не должен быть короткой заменой интерфейса", index.length > 45000],
  ["есть форма добавления рабочего дня", index.includes('id="addDayForm"')],
  ["есть явный ввод даты", index.includes('id="workDate"')],
  ["есть ввод часов и минут", index.includes('id="workHours"') && index.includes('id="workMinutes"')],
  ["есть поле паркинга", index.includes('id="workParking"')],
  ["есть поле ночевки", index.includes('id="workOvernight"')],
  ["есть раскрываемый список записей", index.includes('id="recordsPanel"')],
  ["есть расчет формулы итога", index.includes("sumFormula")],
  ["есть недельная статистика", index.includes("weekDate") && index.includes("weekPrev") && index.includes("weekNext")],
  ["есть месячная статистика", index.includes("monthDate") && index.includes("monthPrev") && index.includes("monthNext")],
  ["есть защищенная авторизация", server.includes('readSignedCookie(req, "nanny_oauth_state")')],
  ["OAuth state не хранится в памяти процесса", !server.includes("oauthStates")],
  ["сервер умеет читать DATABASE_URL", server.includes("DATABASE_URL")],
  ["сервер умеет писать аудит действий", server.includes("appendAuditLog")]
];

const failed = checks.filter(([, ok]) => !ok);

if (failed.length) {
  console.error("Release check failed:");
  for (const [message] of failed) {
    console.error(`- ${message}`);
  }
  process.exit(1);
}

console.log("Release check passed.");
