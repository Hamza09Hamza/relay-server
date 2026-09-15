/**
 * Minimal structured logger — formats every line as:
 *   [LEVEL] [Module] message  (+ data if provided)
 *
 * Colors work in any ANSI-capable terminal (VS Code, macOS Terminal, tmux).
 * In production (NODE_ENV=production) colors are stripped automatically.
 */

const useColors = process.env.NODE_ENV !== 'production' && process.stdout.isTTY;

const C = {
  reset:  useColors ? '\x1b[0m'  : '',
  bold:   useColors ? '\x1b[1m'  : '',
  dim:    useColors ? '\x1b[2m'  : '',
  // Levels
  info:   useColors ? '\x1b[36m' : '', // cyan
  warn:   useColors ? '\x1b[33m' : '', // yellow
  error:  useColors ? '\x1b[31m' : '', // red
  debug:  useColors ? '\x1b[90m' : '', // grey
  // Module tag
  tag:    useColors ? '\x1b[35m' : '', // magenta
};

function timestamp() {
  const now = new Date();
  const hh = now.getHours().toString().padStart(2, '0');
  const mm = now.getMinutes().toString().padStart(2, '0');
  const ss = now.getSeconds().toString().padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

function format(level, color, module, message, data) {
  const ts   = `${C.dim}${timestamp()}${C.reset}`;
  const lvl  = `${color}${C.bold}${level.padEnd(5)}${C.reset}`;
  const mod  = module ? `${C.tag}[${module}]${C.reset}` : '';
  const msg  = `${color}${message}${C.reset}`;
  const line = [ts, lvl, mod, msg].filter(Boolean).join(' ');
  if (data !== undefined) {
    const extra = typeof data === 'string' ? data : JSON.stringify(data, null, 0);
    return `${line} ${C.dim}${extra}${C.reset}`;
  }
  return line;
}

const logger = {
  info:  (module, message, data) => console.log(format('INFO',  C.info,  module, message, data)),
  warn:  (module, message, data) => console.warn(format('WARN',  C.warn,  module, message, data)),
  error: (module, message, data) => console.error(format('ERROR', C.error, module, message, data)),
  debug: (module, message, data) => {
    if (process.env.DEBUG_LOG) console.log(format('DEBUG', C.debug, module, message, data));
  },

  /** Shorthand factories — bind a module prefix once. */
  forModule(module) {
    return {
      info:  (msg, data) => logger.info(module, msg, data),
      warn:  (msg, data) => logger.warn(module, msg, data),
      error: (msg, data) => logger.error(module, msg, data),
      debug: (msg, data) => logger.debug(module, msg, data),
    };
  },
};

module.exports = logger;
