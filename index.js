/**
 * Relay Server - HTTP + JWT
 * Windows Clipboard text/image sync + file transfer for LAN use.
 */

"use strict";

require("dotenv").config();

const http = require("http");
const { execFile } = require("child_process");
const { promisify } = require("util");
const fs = require("fs");
const fsp = fs.promises;
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");

const execFileAsync = promisify(execFile);

// -------------------------------------------------------------
// Environment
// -------------------------------------------------------------

const PORT = parsePositiveInteger(process.env.PORT, 3080);
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_MAX_AGE = (process.env.JWT_MAX_AGE || "").trim();
const ALLOWED_SUBNET = (process.env.ALLOWED_SUBNET || "").trim();
const RATE_LIMIT_MAX = parsePositiveInteger(process.env.RATE_LIMIT_MAX, 60);
const RATE_LIMIT_WINDOW_MS = parsePositiveInteger(process.env.RATE_LIMIT_WINDOW_MS, 60_000);
const HELPER_MAX_BUFFER_MB = parsePositiveInteger(process.env.HELPER_MAX_BUFFER_MB, 220);
const HELPER_MAX_BUFFER = HELPER_MAX_BUFFER_MB * 1024 * 1024;
const CLIPBOARD_MAX_FILE_MB = parsePositiveInteger(process.env.CLIPBOARD_MAX_FILE_MB, 100);

if (!JWT_SECRET) {
  logError("JWT_SECRET is not defined in the .env file.");
  process.exit(1);
}

if (process.platform !== "win32") {
  logError("Relay is Windows-only. This server must be started on Windows.");
  process.exit(1);
}

// -------------------------------------------------------------
// Paths
// -------------------------------------------------------------

const TMP_DIR = path.join(os.tmpdir(), "relay");
const DOWNLOAD_DIR = path.join(os.homedir(), "Downloads", "Relay");

const CLIP_EXE = path.join(TMP_DIR, "cbsync_clip.exe");
const CLIP_CS = path.join(TMP_DIR, "cbsync_clip.cs");
const CLIP_HASH = path.join(TMP_DIR, "cbsync_clip.sha256");

const CSC_PATH_64 = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe";
const CSC_PATH_32 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe";

const DEFAULT_ALLOWED_FILE_ROOTS = os.homedir();
const ALLOWED_FILE_ROOTS_CONFIG = process.env.ALLOWED_FILE_ROOTS || DEFAULT_ALLOWED_FILE_ROOTS;

let allowedFileRoots = [];
let helperReadyPromise = null;

// Pre-compiled regex constants — avoids recompilation on every call
const RE_DATA_URI     = /^data:[^;]+;base64,/;
const RE_TEMP_FILE    = /^[0-9a-fA-F-]+\.(txt|png)$/;
const RE_RESERVED_WIN = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
const RE_UNSAFE_CHARS = /[<>:"/\\|?*\x00-\x1F]/g;
const RE_WHITESPACE   = /\s+/g;
const RE_TRAILING_DOT = /[. ]+$/g;
const RE_BOM          = /^\uFEFF/;
const RE_TRAILING_NL  = /\r?\n$/;
const RE_MAXBUFFER    = /maxBuffer/i;
const RE_172_PRIVATE  = /^172\.(1[6-9]|2\d|3[0-1])\./;

// Image extensions as a Set for O(1) lookup instead of Array.indexOf O(n)
// (Mirrors the C# helper's IsImageExtension list — JS side isn't used at runtime
//  but kept for consistency if future JS-side filtering is added.)
const IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp"]);

// JWT verify options object — built once, reused on every authenticated request
const JWT_VERIFY_OPTIONS = JWT_MAX_AGE ? { maxAge: JWT_MAX_AGE } : undefined;

function tmpFile(ext) {
  return path.join(TMP_DIR, `${crypto.randomUUID()}.${ext}`);
}

// -------------------------------------------------------------
// Logging
// -------------------------------------------------------------

// Single implementation — eliminates four near-identical wrapper functions
function writeLog(level, message, meta, isError = false) {
  const suffix = meta ? ` ${JSON.stringify(meta)}` : "";
  const line = `[${new Date().toISOString()}] ${level} ${message}${suffix}`;

  if (isError)          console.error(line);
  else if (level === "WARN") console.warn(line);
  else                  console.log(line);
}

// Thin aliases kept for call-site readability — zero overhead
const logInfo  = (msg, meta) => writeLog("INFO",  msg, meta);
const logWarn  = (msg, meta) => writeLog("WARN",  msg, meta);
const logError = (msg, meta) => writeLog("ERROR", msg, meta, true);

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function truncateLog(value, maxLength = 1000) {
  const text = String(value || "");
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}... [truncated ${text.length - maxLength} chars]`;
}

// -------------------------------------------------------------
// C# Clipboard Helper
// -------------------------------------------------------------

const CLIP_HELPER_VERSION = "2026-05-09.4";

const CLIPBOARD_HELPER_SOURCE = String.raw`
using System;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;
using System.Threading;

class Program
{
    static int exitCode = 0;
    static string[] globalArgs;

    static int Main(string[] args)
    {
        globalArgs = args;
        Thread thread = new Thread(delegate() { exitCode = Run(globalArgs); });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        return exitCode;
    }

    static int Run(string[] args)
    {
        try
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            if (args.Length < 1)
            {
                Console.Error.WriteLine("Missing command.");
                return 1;
            }

            string cmd = args[0];

            if (cmd == "read") return ReadClipboard();

            if (cmd == "write-text")
            {
                if (args.Length < 2)
                {
                    Console.Error.WriteLine("Missing text file path.");
                    return 1;
                }

                string text = File.ReadAllText(args[1], System.Text.Encoding.UTF8);
                if (text.Length == 0)
                {
                    Clipboard.Clear();
                }
                else
                {
                    Clipboard.SetText(text);
                }
                Console.WriteLine("OK");
                return 0;
            }

            if (cmd == "write-image")
            {
                if (args.Length < 2)
                {
                    Console.Error.WriteLine("Missing image file path.");
                    return 1;
                }

                using (Bitmap bmp = new Bitmap(args[1]))
                {
                    Clipboard.SetImage(bmp);
                }

                Console.WriteLine("OK");
                return 0;
            }

            Console.Error.WriteLine("Unknown command: " + cmd);
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            return 1;
        }
    }

    static int ReadClipboard()
    {
        if (Clipboard.ContainsImage())
        {
            Image image = Clipboard.GetImage();
            if (image != null)
            {
                using (image)
                {
                    return WriteImagePayload(image);
                }
            }
        }

        if (Clipboard.ContainsFileDropList())
        {
            var files = Clipboard.GetFileDropList();
            if (files.Count > 0)
            {
                string filePath = files[0];
                string ext = Path.GetExtension(filePath).ToLowerInvariant();

                if (IsImageExtension(ext) && TryWriteImageFileAsPng(filePath))
                {
                    return 0;
                }

                return WriteFilePayload(filePath);
            }
        }

        if (Clipboard.ContainsText())
        {
            Console.WriteLine("text");
            Console.Write(Clipboard.GetText());
            return 0;
        }

        Console.WriteLine("empty");
        return 0;
    }

    static bool IsImageExtension(string ext)
    {
        string[] imgExts = { ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp" };
        return Array.IndexOf(imgExts, ext) >= 0;
    }

    static bool TryWriteImageFileAsPng(string filePath)
    {
        try
        {
            using (Image image = Image.FromFile(filePath))
            {
                WriteImagePayload(image);
                return true;
            }
        }
        catch
        {
            return false;
        }
    }

    static int WriteImagePayload(Image image)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            image.Save(ms, ImageFormat.Png);
            Console.WriteLine("image");
            Console.WriteLine(Convert.ToBase64String(ms.ToArray()));
            return 0;
        }
    }

    static int WriteFilePayload(string filePath)
    {
        string fileName = Path.GetFileName(filePath);

        long maxMb = 100;
        string envLimit = Environment.GetEnvironmentVariable("CLIPBOARD_MAX_FILE_MB");

        if (!String.IsNullOrWhiteSpace(envLimit))
        {
            long parsed;
            if (Int64.TryParse(envLimit, out parsed) && parsed > 0)
            {
                maxMb = parsed;
            }
        }

        long maxBytes = maxMb * 1024L * 1024L;
        FileInfo info = new FileInfo(filePath);

        if (info.Length > maxBytes)
        {
            Console.Error.WriteLine(
                "Clipboard file is too large for base64 transfer. File size: " +
                info.Length +
                " bytes. Limit: " +
                maxBytes +
                " bytes. Use a smaller file or transfer large files directly instead of through clipboard base64."
            );
            return 2;
        }

        string fileBase64 = Convert.ToBase64String(File.ReadAllBytes(filePath));
        Console.WriteLine("file");
        Console.WriteLine(fileName);
        Console.WriteLine(fileBase64);
        return 0;
    }
}
`;

async function ensureClipboardHelper() {
  if (!helperReadyPromise) {
    helperReadyPromise = buildClipboardHelperIfNeeded().catch((err) => {
      helperReadyPromise = null;
      throw err;
    });
  }
  return helperReadyPromise;
}

async function buildClipboardHelperIfNeeded() {
  await fsp.mkdir(TMP_DIR, { recursive: true });

  // Resolve csc.exe path: check 64-bit first, fall back to 32-bit.
  // Both checks run concurrently to avoid two sequential I/O waits.
  const [has64, has32] = await Promise.all([pathExists(CSC_PATH_64), pathExists(CSC_PATH_32)]);
  const csc = has64 ? CSC_PATH_64 : has32 ? CSC_PATH_32 : null;

  if (!csc) {
    throw new Error("csc.exe was not found. .NET Framework 4.x must be installed.");
  }

  const sourceHash = sha256(`${CLIP_HELPER_VERSION}\n${CLIPBOARD_HELPER_SOURCE}`);

  const [exeExists, previousHash] = await Promise.all([
    pathExists(CLIP_EXE),
    readTextIfExists(CLIP_HASH)
  ]);

  if (exeExists && previousHash === sourceHash) return;

  await fsp.writeFile(CLIP_CS, CLIPBOARD_HELPER_SOURCE, "utf8");

  try {
    await execFileAsync(csc, ["/nologo", "/target:exe", `/out:${CLIP_EXE}`, CLIP_CS], {
      windowsHide: true,
      maxBuffer: 2 * 1024 * 1024
    });
  } catch (err) {
    const detail = String(err.stderr || err.stdout || err.message || "").trim();
    throw new Error(`Clipboard helper compilation failed. ${detail}`.trim());
  }

  await fsp.writeFile(CLIP_HASH, sourceHash, "utf8");
  logInfo("Clipboard helper compiled.", { path: CLIP_EXE });
}

async function runClipboardHelper(args) {
  await ensureClipboardHelper();

  try {
    const { stdout } = await execFileAsync(CLIP_EXE, args, {
      encoding: "utf8",
      windowsHide: true,
      maxBuffer: HELPER_MAX_BUFFER
    });
    return stdout;
  } catch (err) {
    const stderr  = String(err.stderr  || "").trim();
    const message = String(err.message || "").trim();

    if (err.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" || RE_MAXBUFFER.test(message)) {
      throw new Error(
        `Clipboard helper output exceeded the buffer limit. Use a smaller file or increase HELPER_MAX_BUFFER_MB. Current limit: ${HELPER_MAX_BUFFER_MB} MB.`
      );
    }

    throw new Error(stderr || message || "Clipboard helper failed.");
  }
}

// -------------------------------------------------------------
// Clipboard Read / Write
// -------------------------------------------------------------

async function readClipboard() {
  const output = await runClipboardHelper(["read"]);

  if (!output) return { type: "empty" };

  const nl = output.indexOf("\n");

  if (nl === -1) {
    const marker = output.trim();
    // Only "empty" and "text" (with empty data) are valid single-line results
    if (marker === "empty") return { type: "empty" };
    if (marker === "text")  return { type: "text", data: "" };
    return { type: "empty" };
  }

  const type = output.slice(0, nl).trim();
  const rest = output.slice(nl + 1);

  switch (type) {
    case "empty":
      return { type: "empty" };

    case "image":
      return { type: "image", mimeType: "image/png", data: trimOneTrailingNewline(rest) };

    case "text":
      return { type: "text", data: rest };

    case "file": {
      const nl2 = rest.indexOf("\n");
      if (nl2 === -1) return { type: "empty" };
      return {
        type: "file",
        name: rest.slice(0, nl2).trim(),
        data: trimOneTrailingNewline(rest.slice(nl2 + 1))
      };
    }

    default:
      return { type: "empty" };
  }
}

async function writeClipboard(type, data) {
  if (type === "text") {
    const file = tmpFile("txt");
    try {
      await fsp.writeFile(file, String(data ?? ""), "utf8");
      await runClipboardHelper(["write-text", file]);
    } finally {
      await safeUnlink(file);
    }
    return;
  }

  if (type === "image") {
    const file = tmpFile("png");
    try {
      const clean = String(data).replace(RE_DATA_URI, "");
      await fsp.writeFile(file, Buffer.from(clean, "base64"));
      await runClipboardHelper(["write-image", file]);
    } finally {
      await safeUnlink(file);
    }
    return;
  }

  throw createHttpError(400, `Unsupported clipboard type: ${type}`);
}

function parseClipboardPayload(body) {
  if (typeof body === "string") {
    const cleanBody = body.replace(RE_BOM, "");
    const idx = cleanBody.indexOf("\n");

    if (idx === -1) {
      throw createHttpError(400, "Invalid text payload. Expected '<type>\\n<data>'.");
    }

    const type = cleanBody.slice(0, idx).trim();
    validateClipboardWriteType(type);
    return { type, data: cleanBody.slice(idx + 1) };
  }

  if (body && typeof body === "object") {
    const type = typeof body.type === "string" ? body.type.trim() : body.type;
    validateClipboardWriteType(type);
    return { type, data: body.data };
  }

  return {};
}

function validateClipboardWriteType(type) {
  if (type !== "text" && type !== "image") {
    throw createHttpError(400, `Unsupported clipboard type: ${type || "missing"}`);
  }
}

function trimOneTrailingNewline(value) {
  return String(value).replace(RE_TRAILING_NL, "");
}

// -------------------------------------------------------------
// File Security / Transfer Helpers
// -------------------------------------------------------------

async function initAllowedFileRoots() {
  const roots = ALLOWED_FILE_ROOTS_CONFIG
    .split(";")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map(expandHomePath)
    .map((entry) => path.resolve(entry));

  // Deduplicate before any async work
  const uniqueRoots = [...new Set(roots)];
  const resolvedRoots = [];

  // Resolve all roots concurrently
  await Promise.all(uniqueRoots.map(async (root) => {
    try {
      resolvedRoots.push(await fsp.realpath(root));
    } catch (err) {
      logWarn("Allowed file root does not exist and will be ignored.", {
        root,
        error: err.message
      });
    }
  }));

  if (resolvedRoots.length === 0) {
    throw new Error("No valid allowed file roots are available.");
  }

  allowedFileRoots = resolvedRoots;
}

async function resolveAllowedExistingFile(filePath) {
  if (!filePath || typeof filePath !== "string") {
    throw createHttpError(400, "The path query parameter is required.");
  }

  let realPath;
  try {
    realPath = await fsp.realpath(path.resolve(filePath));
  } catch (err) {
    if (err.code === "ENOENT") throw createHttpError(404, "File not found.");
    throw err;
  }

  if (!isInsideAnyAllowedRoot(realPath)) {
    throw createHttpError(403, "Access to this path is not allowed.");
  }

  const stat = await fsp.stat(realPath);

  if (!stat.isFile()) {
    throw createHttpError(400, "The specified path is not a file.");
  }

  return { realPath, stat };
}

function isInsideAnyAllowedRoot(candidatePath) {
  return allowedFileRoots.some((root) => isPathInsideRoot(candidatePath, root));
}

function isPathInsideRoot(candidatePath, rootPath) {
  const candidate = normalizePathForCompare(candidatePath);
  const root      = normalizePathForCompare(rootPath);
  const rootWithSep = root.endsWith(path.sep) ? root : `${root}${path.sep}`;
  return candidate === root || candidate.startsWith(rootWithSep);
}

function normalizePathForCompare(value) {
  const normalized = path.normalize(value);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function expandHomePath(value) {
  if (value === "~") return os.homedir();
  if (value.startsWith(`~${path.sep}`) || value.startsWith("~/")) {
    return path.join(os.homedir(), value.slice(2));
  }
  return value;
}

function sanitizeFileName(name) {
  const rawBaseName = path.win32.basename(String(name));

  let safeName = rawBaseName
    .replace(RE_UNSAFE_CHARS, "_")
    .replace(RE_WHITESPACE,   " ")
    .trim()
    .replace(RE_TRAILING_DOT, "");

  if (!safeName) return "";

  if (RE_RESERVED_WIN.test(safeName)) {
    safeName = `_${safeName}`;
  }

  return safeName;
}

async function writeUniqueDownloadFile(name, data) {
  const safeName = sanitizeFileName(name);
  if (!safeName) throw createHttpError(400, "Invalid file name.");

  const ext    = path.extname(safeName);
  const base   = path.basename(safeName, ext);
  const clean  = String(data).replace(RE_DATA_URI, "");
  const buffer = Buffer.from(clean, "base64");

  for (let i = 0; i < 10_000; i++) {
    const candidateName = i === 0 ? safeName : `${base}(${i})${ext}`;
    const candidatePath = path.join(DOWNLOAD_DIR, candidateName);
    let handle;

    try {
      handle = await fsp.open(candidatePath, "wx");
      await handle.writeFile(buffer);
      await handle.close();
      return candidatePath;
    } catch (err) {
      if (handle) {
        try { await handle.close(); } catch {}
      }
      if (err.code === "EEXIST") continue;
      throw err;
    }
  }

  throw new Error("Could not find an available file name.");
}

// -------------------------------------------------------------
// General Helpers
// -------------------------------------------------------------

async function pathExists(filePath) {
  try {
    await fsp.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readTextIfExists(filePath) {
  try {
    return await fsp.readFile(filePath, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return "";
    throw err;
  }
}

async function safeUnlink(filePath) {
  try {
    if (filePath) await fsp.unlink(filePath);
  } catch (err) {
    if (err.code !== "ENOENT") {
      logWarn("Temporary file could not be removed.", {
        path: filePath,
        error: err.message
      });
    }
  }
}

async function cleanupTempFiles() {
  await fsp.mkdir(TMP_DIR, { recursive: true });
  const entries = await fsp.readdir(TMP_DIR, { withFileTypes: true });
  let removed = 0;

  await Promise.all(entries.map(async (entry) => {
    if (!entry.isFile() || !RE_TEMP_FILE.test(entry.name)) return;
    await safeUnlink(path.join(TMP_DIR, entry.name));
    removed += 1;
  }));

  if (removed > 0) {
    logInfo("Removed leftover temporary files.", { count: removed });
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function createHttpError(statusCode, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function getClientIP(req) {
  return (req.socket.remoteAddress || "")
    .replace(/^::ffff:/, "")
    .replace(/^::1$/,    "127.0.0.1");
}

function isLoopbackIP(ip) {
  return ip === "127.0.0.1" || ip === "localhost";
}

function isPrivateLanIP(ip) {
  return (
    ip.startsWith("10.")      ||
    ip.startsWith("192.168.") ||
    RE_172_PRIVATE.test(ip)
  );
}

function isIPAllowed(ip) {
  if (isLoopbackIP(ip)) return true;
  if (ALLOWED_SUBNET)   return ip.startsWith(ALLOWED_SUBNET);
  return isPrivateLanIP(ip);
}

function getLanAddress() {
  const interfaces = os.networkInterfaces();
  const addresses  = [];

  for (const details of Object.values(interfaces)) {
    for (const item of details || []) {
      if (item.family === "IPv4" && !item.internal) addresses.push(item.address);
    }
  }

  return (
    addresses.find((a) => a.startsWith(ALLOWED_SUBNET)) ||
    addresses[0] ||
    "0.0.0.0"
  );
}

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

// -------------------------------------------------------------
// Express
// -------------------------------------------------------------

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", false);

app.use(helmet({ contentSecurityPolicy: false }));

app.use((req, res, next) => {
  const ip = getClientIP(req);
  if (!isIPAllowed(ip)) {
    logWarn("Blocked unauthorized IP.", { ip });
    return res.status(403).json({ error: "Access denied." });
  }
  req.clientIP = ip;
  next();
});

app.use(rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests." }
}));

app.use(express.json({ limit: "50mb" }));
app.use(express.text({ limit: "200mb", type: "text/*" }));

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token is required." });
  }

  try {
    jwt.verify(auth.slice(7), JWT_SECRET, JWT_VERIFY_OPTIONS);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token." });
  }
}

// -------------------------------------------------------------
// Routes - Clipboard
// -------------------------------------------------------------

app.get("/status", requireAuth, (req, res) => {
  res.json({ ok: true, server: "relay", ip: req.clientIP });
});

app.get("/relay", requireAuth, asyncHandler(async (req, res) => {
  const content = await readClipboard();
  logInfo("Clipboard read.", { ip: req.clientIP, type: content.type });
  res.json(content);
}));

app.post("/relay", requireAuth, asyncHandler(async (req, res) => {
  const payload = parseClipboardPayload(req.body);

  if (!payload.type || payload.data == null) {
    throw createHttpError(400, "type and data are required.");
  }

  await writeClipboard(payload.type, payload.data);
  logInfo("Clipboard written.", { ip: req.clientIP, type: payload.type });
  res.json({ ok: true, type: payload.type });
}));

// -------------------------------------------------------------
// Routes - File Transfer
// -------------------------------------------------------------

app.post("/file", requireAuth, asyncHandler(async (req, res) => {
  const { name, data } = req.body || {};

  if (!name || !data) {
    throw createHttpError(400, "name and data are required.");
  }

  const destPath = await writeUniqueDownloadFile(name, data);
  // stat + basename in parallel-friendly fashion (stat is the only async call here)
  const stat     = await fsp.stat(destPath);
  const fileName = path.basename(destPath);
  const sizeKB   = (stat.size / 1024).toFixed(1);

  logInfo("File received.", { ip: req.clientIP, file: fileName, sizeKB });
  res.json({ ok: true, saved: fileName, path: destPath, type: "file" });
}));

app.get("/file", requireAuth, asyncHandler(async (req, res) => {
  const { realPath, stat } = await resolveAllowedExistingFile(req.query.path);
  // Read file and derive metadata — buffer read is the only async call
  const buffer   = await fsp.readFile(realPath);
  const fileName = path.basename(realPath);
  const data     = buffer.toString("base64");
  const sizeKB   = (stat.size / 1024).toFixed(1);

  logInfo("File sent.", { ip: req.clientIP, file: fileName, sizeKB });
  res.json({ ok: true, name: fileName, type: "file", data });
}));

app.get("/files", requireAuth, asyncHandler(async (req, res) => {
  const entries = await fsp.readdir(DOWNLOAD_DIR, { withFileTypes: true });

  const files = (
    await Promise.all(
      entries.map(async (entry) => {
        if (!entry.isFile() || entry.name.startsWith(".")) return null;

        const filePath = path.join(DOWNLOAD_DIR, entry.name);
        try {
          const stat = await fsp.stat(filePath);
          return {
            name:     entry.name,
            size:     stat.size,
            modified: stat.mtime.toISOString(),
            mtimeMs:  stat.mtimeMs
          };
        } catch (err) {
          if (err.code === "ENOENT") return null;
          throw err;
        }
      })
    )
  )
    .filter(Boolean)
    .sort((a, b) => b.mtimeMs - a.mtimeMs)
    .slice(0, 50)
    .map(({ mtimeMs, ...file }) => file); // strip sort key from response

  res.json({ ok: true, dir: DOWNLOAD_DIR, files });
}));

// -------------------------------------------------------------
// Error handlers
// -------------------------------------------------------------

app.use((req, res) => {
  res.status(404).json({ error: "Not found." });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err.type === "entity.too.large") {
    logWarn("Request body too large.", { ip: req.clientIP, path: req.path });
    return res.status(413).json({ error: "Request body is too large." });
  }

  if (err instanceof SyntaxError && "body" in err) {
    logWarn("Invalid JSON body.", { ip: req.clientIP, path: req.path });
    return res.status(400).json({ error: "Invalid JSON body." });
  }

  const statusCode    = err.statusCode || 500;
  const publicMessage = statusCode < 500 ? err.message : "Internal server error.";

  logError("Request failed.", {
    ip:         req.clientIP,
    method:     req.method,
    path:       req.path,
    statusCode,
    error:      truncateLog(err.message)
  });

  return res.status(statusCode).json({ error: publicMessage });
});

// -------------------------------------------------------------
// Startup
// -------------------------------------------------------------

async function init() {
  await fsp.mkdir(TMP_DIR,     { recursive: true });
  await fsp.mkdir(DOWNLOAD_DIR, { recursive: true });

  await cleanupTempFiles();
  await initAllowedFileRoots();
  await ensureClipboardHelper();

  const server = http.createServer(app);

  server.listen(PORT, "0.0.0.0", () => {
    logInfo("Relay is running.", {
      url:             `http://${getLanAddress()}:${PORT}`,
      allowedSubnet:   `${ALLOWED_SUBNET}*`,
      downloadDir:     DOWNLOAD_DIR,
      allowedFileRoots
    });
  });
}

init().catch((err) => {
  logError("Relay failed to start.", { error: truncateLog(err.message) });
  process.exit(1);
});