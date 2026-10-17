import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import bcrypt from 'bcryptjs';

function ask(question) {
  const terminal = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolveAnswer) => terminal.question(question, (answer) => {
    terminal.close();
    resolveAnswer(answer.trim());
  }));
}

function askPassword() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Run this setup command in an interactive terminal.');
  }

  process.stdout.write('Admin password (minimum 14 characters): ');
  return new Promise((resolvePassword, rejectPassword) => {
    let password = '';
    process.stdin.setRawMode(true);
    process.stdin.resume();
    const onKeypress = (chunk) => {
      const key = chunk.toString();
      if (key === '\u0003') {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.off('data', onKeypress);
        process.stdout.write('\n');
        rejectPassword(new Error('Admin setup cancelled.'));
      } else if (key === '\r' || key === '\n') {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.off('data', onKeypress);
        process.stdout.write('\n');
        resolvePassword(password);
      } else if (key === '\u007f' || key === '\b') {
        if (password.length) {
          password = password.slice(0, -1);
          process.stdout.write('\b \b');
        }
      } else if (key >= ' ' && key !== '\u001b') {
        password += key;
        process.stdout.write('*');
      }
    };
    process.stdin.on('data', onKeypress);
  });
}

function setEnvValue(source, key, value) {
  const line = `${key}=${value}`;
  const pattern = new RegExp(`^${key}=.*$`, 'm');
  if (pattern.test(source)) return source.replace(pattern, line);
  return `${source.trimEnd()}${source.trim() ? '\n' : ''}${line}\n`;
}

async function main() {
  const email = (await ask('Admin email: ')).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    throw new Error('Enter a valid admin email address.');
  }
  const password = await askPassword();
  if (password.length < 14 || password.length > 200) {
    throw new Error('Admin password must be between 14 and 200 characters.');
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const sessionSecret = randomBytes(48).toString('base64url');
  const envPath = resolve(dirname(fileURLToPath(import.meta.url)), '../.env');
  let contents = '';
  try {
    contents = await readFile(envPath, 'utf8');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  contents = setEnvValue(contents, 'ADMIN_EMAIL', email);
  contents = setEnvValue(contents, 'ADMIN_PASSWORD_HASH', passwordHash);
  contents = setEnvValue(contents, 'ADMIN_SESSION_SECRET', sessionSecret);
  await writeFile(envPath, contents, { encoding: 'utf8', mode: 0o600 });
  console.log('Admin sign-in configured in server/.env. Restart the API to apply it.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}