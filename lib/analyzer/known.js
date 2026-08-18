const core = [
  "@deepseek-ai/dsh", "@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web", "@deepseek-ai/dsh-web-app",
  "@deepseek-ai/dsh-headless", "@deepseek-ai/dsh-cli", "@deepseek-ai/dsh-app-boot",
  "@deepseek-ai/dsh-agent", "@deepseek-ai/dsh-llm", "@deepseek-ai/dsh-session", "@deepseek-ai/dsh-tools",
  "@deepseek-ai/dsh-settings", "@deepseek-ai/dsh-cordis-host-runner", "@deepseek-ai/dsh-host-webserver",
  "@deepseek-ai/dsh-sandbox", "@deepseek-ai/dsh-fs-sandbox", "@deepseek-ai/dsh-sandbox-policy",
  "@deepseek-ai/dsh-credentials-local", "@deepseek-ai/dsh-settings-file", "@deepseek-ai/dsh-session-persistence-jsonl",
  "@deepseek-ai/dsh-attachment-local", "@deepseek-ai/dsh-session-query-sqlite", "@deepseek-ai/dsh-skill",
  "@deepseek-ai/dsh-skill-filesystem", "@deepseek-ai/dsh-tool-web", "@deepseek-ai/dsh-tool-bash",
  "@deepseek-ai/dsh-tool-fs", "@deepseek-ai/dsh-tool-subagent", "@deepseek-ai/dsh-tool-workflow",
  "@deepseek-ai/dsh-tool-ralph", "@deepseek-ai/dsh-tool-goal", "@deepseek-ai/dsh-tool-jobs",
  "@deepseek-ai/dsh-tool-todo", "@deepseek-ai/dsh-tool-skill", "@deepseek-ai/dsh-tool-ask-user",
  "@deepseek-ai/dsh-tool-str-replace-editor", "@deepseek-ai/dsh-tool-bash-persistent", "@deepseek-ai/dsh-tool-pwsh",
  "@deepseek-ai/dsh-commands", "@deepseek-ai/dsh-command-goal", "@deepseek-ai/dsh-command-compact",
  "@deepseek-ai/dsh-api-gateway", "@deepseek-ai/dsh-api-remotes", "@deepseek-ai/dsh-typert-registry",
  "@deepseek-ai/dsh-typert-loader", "@deepseek-ai/dsh-agent-presets", "@deepseek-ai/dsh-persona",
  "@deepseek-ai/dsh-system-prompt", "@deepseek-ai/dsh-plan-mode", "@deepseek-ai/dsh-goal",
  "@deepseek-ai/dsh-goal-round-driver", "@deepseek-ai/dsh-compaction", "@deepseek-ai/dsh-compaction-basic",
  "@deepseek-ai/dsh-spill", "@deepseek-ai/dsh-spill-local", "@deepseek-ai/dsh-spill-policy",
  "@deepseek-ai/dsh-session-title", "@deepseek-ai/dsh-session-title-llm", "@deepseek-ai/dsh-session-stats",
  "@deepseek-ai/dsh-session-projection", "@deepseek-ai/dsh-session-reference", "@deepseek-ai/dsh-token-meter",
  "@deepseek-ai/dsh-llm-deepseek", "@deepseek-ai/dsh-llm-pi-ai", "@deepseek-ai/dsh-llm-retry",
  "@deepseek-ai/dsh-jobs-local", "@deepseek-ai/dsh-timeout", "@deepseek-ai/dsh-time-context",
  "@deepseek-ai/dsh-bash-local", "@deepseek-ai/dsh-bash-sandbox", "@deepseek-ai/dsh-pwsh-local",
  "@deepseek-ai/dsh-pwsh-sandbox", "@deepseek-ai/dsh-sandbox-local", "@deepseek-ai/dsh-subprocess",
  "@deepseek-ai/dsh-subprocess-local", "@deepseek-ai/dsh-terminal", "@deepseek-ai/dsh-terminal-bash",
  "@deepseek-ai/dsh-workspace", "@deepseek-ai/dsh-home-paths", "@deepseek-ai/dsh-launch-environment",
  "@deepseek-ai/dsh-anonymous-user-id", "@deepseek-ai/dsh-brand", "@deepseek-ai/dsh-invariants",
  "@deepseek-ai/dsh-scope", "@deepseek-ai/dsh-storage", "@deepseek-ai/dsh-storage-domain",
  "@deepseek-ai/dsh-storage-json", "@deepseek-ai/dsh-atomic-write", "@deepseek-ai/dsh-schedule",
  "@deepseek-ai/dsh-mcp-client", "@deepseek-ai/dsh-code-runtime", "@deepseek-ai/dsh-fs",
  "@deepseek-ai/dsh-fs-local", "@deepseek-ai/dsh-fs-observation-policy", "@deepseek-ai/dsh-output-retention",
  "@deepseek-ai/dsh-user-approval", "@deepseek-ai/dsh-user-questions", "@deepseek-ai/dsh-permission-presets",
  "@deepseek-ai/dsh-repeat-tool-reminder", "@deepseek-ai/dsh-session-checkpoint-policy",
  "@deepseek-ai/dsh-tool-call-timeout-policy", "@deepseek-ai/dsh-session-telemetry-otel",
  "@deepseek-ai/dsh-command-feedback", "@deepseek-ai/dsh-message-feedback", "@deepseek-ai/dsh-skill-badge",
  "@deepseek-ai/dsh-subagent", "@deepseek-ai/dsh-subagent-in-process-driver", "@deepseek-ai/dsh-subagent-spawn-in-process",
  "@deepseek-ai/dsh-subagent-fork-in-process", "@deepseek-ai/dsh-subagent-report", "@deepseek-ai/dsh-tool-subagent-report",
  "@deepseek-ai/dsh-tool-subagent-control", "@deepseek-ai/dsh-workflow", "@deepseek-ai/dsh-workflow-worker-thread",
  "@deepseek-ai/dsh-web-search-deepseek", "@deepseek-ai/dsh-tmux-context", "@deepseek-ai/dsh-shell",
  "@deepseek-ai/dsh-shell-env", "@deepseek-ai/dsh-session-log-export", "@deepseek-ai/dsh-host-apiproxy",
  "@deepseek-ai/dsh-host-frontend-static", "@deepseek-ai/dsh-host-directory-picker", "@deepseek-ai/dsh-host-plugin-inventory",
  "@deepseek-ai/cordis", "@deepseek-ai/cordis-plugin-loader", "@deepseek-ai/cordis-plugin-include",
  "@deepseek-ai/cordis-plugin-hmr", "@deepseek-ai/cordis-plugin-timer", "@deepseek-ai/cordis-plugin-group",
  "@deepseek-ai/cosmokit", "@deepseek-ai/schemastery", "@deepseek-ai/dsh-cmdline", "@deepseek-ai/dsh-client-web"
];
const community = [
  "@linxin666/dsh-web-ui-all", "@linxin666/dsh-pet", "@linxin666/dsh-live-stats",
  "@linxin666/dsh-task-board", "@linxin666/dsh-client-ui-task-board", "@linxin666/dsh-ssh",
  "@linxin666/dsh-aionui-panel", "@linxin666/dsh-client-ui-aionui-panel", "@linxin666/dsh-liangshen",
  "@linxin666/dsh-client-ui-web-ui-settings", "@linxin666/dsh-client-ui-git-graph",
  "@linxin666/dsh-client-ui-skin-center", "@linxin666/dsh-skins"
];
const popular = [
  "react", "react-dom", "vue", "angular", "svelte", "next", "nuxt", "vite", "webpack", "rollup",
  "esbuild", "typescript", "tslib", "babel-core", "@babel/core", "@babel/runtime", "jest", "vitest",
  "mocha", "chai", "eslint", "prettier", "axios", "got", "node-fetch", "undici", "ws", "socket.io",
  "express", "koa", "fastify", "hono", "nest", "@nestjs/core", "lodash", "underscore", "ramda",
  "moment", "dayjs", "date-fns", "zod", "joi", "yup", "ajv", "schemastery", "yaml", "js-yaml",
  "dotenv", "cross-env", "commander", "yargs", "inquirer", "chalk", "picocolors", "ora", "debug",
  "winston", "pino", "morgan", "uuid", "nanoid", "crypto-js", "bcrypt", "bcryptjs", "jsonwebtoken",
  "passport", "helmet", "cors", "body-parser", "multer", "sharp", "jimp", "canvas", "puppeteer",
  "playwright", "selenium-webdriver", "cheerio", "jsdom", "turndown", "marked", "markdown-it",
  "highlight.js", "shiki", "prismjs", "tailwindcss", "sass", "less", "postcss", "autoprefixer",
  "style-loader", "css-loader", "react-router", "react-router-dom", "redux", "zustand", "mobx",
  "rxjs", "immer", "i18next", "react-i18next", "clsx", "classnames", "d3", "echarts", "chart.js",
  "three", "webgl", "openai", "@anthropic-ai/sdk", "@google/genai", "langchain", "open", "koffi",
  "node-pty", "chokidar", "glob", "globby", "rimraf", "fs-extra", "mkdirp", "semver", "minimist",
  "tar", "adm-zip", "unzipper", "archiver", "pnpm", "npm", "yarn", "corepack", "tsx",
  "ts-node", "nodemon", "pm2", "forever", "concurrently", "electron", "tauri", "serialize-javascript",
  "protobufjs", "grpc", "@grpc/grpc-js", "bullmq", "ioredis", "redis", "mongodb", "mongoose",
  "sequelize", "pg", "mysql2", "sqlite3", "better-sqlite3", "knex", "typeorm", "prisma"
];

/**
 * Names the typosquat rule compares against: dsh core, known dsh community
 * plugins, and popular npm packages.
 */
export const KNOWN_NAMES = new Set([...core, ...community, ...popular]);

/** Unscoped basenames of every known name. */
export const KNOWN_UNSCOPED = new Set(
  [...core, ...community, ...popular].map((n) => {
    const at = n.indexOf("/");
    return at === -1 ? n : n.slice(at + 1);
  })
);

/**
 * Edit distance <= 1 (insert / delete / substitute) between two names,
 * case-insensitive. Returns the distance.
 */
export function nearMiss(a, b) {
  const x = String(a || "").toLowerCase();
  const y = String(b || "").toLowerCase();
  if (x === y) return 0;
  const la = x.length;
  const lb = y.length;
  if (Math.abs(la - lb) > 1) return 2;
  if (Math.abs(la - lb) === 1) {
    const shorter = la < lb ? x : y;
    const longer = la < lb ? y : x;
    let i = 0;
    let j = 0;
    let edits = 0;
    while (i < shorter.length && j < longer.length) {
      if (shorter[i] !== longer[j]) {
        edits += 1;
        j += 1;
        if (edits > 1) return edits;
        continue;
      }
      i += 1;
      j += 1;
    }
    edits += longer.length - j;
    return edits;
  }
  let edits = 0;
  for (let i = 0; i < la; i++) if (x[i] !== y[i]) edits += 1;
  return edits;
}
