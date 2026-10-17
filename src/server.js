import 'dotenv/config';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import mongoose from 'mongoose';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import Contact from './models/Contact.js';
import adminRouter from './routes/admin.js';

const app = express();
const port = Number(process.env.PORT) || 5000;
const allowedOrigins = [
  ...(process.env.CLIENT_ORIGIN || 'http://localhost:5173').split(','),
  ...(process.env.ADMIN_ORIGIN || 'http://localhost:5174').split(','),
].map((origin) => origin.trim()).filter(Boolean);

app.use(helmet());
app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));

function getDatabaseStatus() {
  if (!process.env.MONGODB_URI) return 'not-configured';
  return ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoose.connection.readyState] ?? 'unknown';
}

const projects = [
  {
    id: 'autovexa',
    name: 'AutoVexa',
    description: 'Online vehicle marketplace with customer, vendor, and admin workflows, inventory search, bookings, invoices, and an agentic AI assistant.',
    technologies: ['React', 'Redux Toolkit', 'Node.js', 'Express', 'MySQL', 'JWT', 'Razorpay'],
    liveUrl: 'https://autovexa.vercel.app',
    sourceUrl: 'https://github.com/sujeethonnappagol/autovexa',
  },
  {
    id: 'krishi-yoga-mandira',
    name: 'Krishi Yoga Mandira',
    description: 'Live client platform with user and admin dashboards, enrollments, attendance, support workflows, UPI payments, and real-time features.',
    technologies: ['React', 'Vite', 'Node.js', 'Express', 'MongoDB', 'JWT', 'Socket.IO'],
    liveUrl: 'https://krishiyogamandira.com',
  },
];

app.get('/api/health', (_request, response) => {
  response.json({ status: 'ok', database: getDatabaseStatus() });
});

app.get('/api/projects', (_request, response) => {
  response.json(projects);
});

app.get('/api/projects/:id', (request, response) => {
  const project = projects.find(({ id }) => id === request.params.id);
  if (!project) return response.status(404).json({ error: 'Project not found.' });
  return response.json(project);
});

app.post('/api/contact', async (request, response, next) => {
  const { name, email, subject, message } = request.body ?? {};
  const values = [name, email, subject, message];
  if (!values.every((value) => typeof value === 'string' && value.trim())) {
    return response.status(400).json({ error: 'Please complete every field.' });
  }
  if (name.trim().length > 80 || subject.trim().length > 120 || message.trim().length > 3000) {
    return response.status(400).json({ error: 'One or more fields exceed the allowed length.' });
  }
  if (email.trim().length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return response.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (!process.env.MONGODB_URI) {
    return response.status(503).json({ error: 'Contact storage is not configured yet. Please use the email link instead.' });
  }
  if (mongoose.connection.readyState !== 1) {
    return response.status(503).json({ error: 'The database is not connected yet. Please try again shortly or use the email link.' });
  }

  try {
    await Contact.create({ name, email, subject, message });
    return response.status(201).json({ message: 'Thanks for reaching out. Your message has been sent.' });
  } catch (error) {
    return next(error);
  }
});

app.use('/api/admin', adminRouter);

app.use((error, _request, response, _next) => {
  console.error('Request failed:', error.name || 'Error');
  response.status(500).json({ error: 'Something went wrong. Please try again later.' });
});

export async function connectDatabase(uri = process.env.MONGODB_URI) {
  if (!uri) return false;
  await mongoose.connect(uri, { dbName: 'sujeet_portfolio', serverSelectionTimeoutMS: 10000 });
  return true;
}

export { app };

const isMainModule = process.argv[1]
  && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMainModule) {
  connectDatabase()
    .then((connected) => {
      if (connected) console.log('Connected to MongoDB');
      else console.warn('MONGODB_URI is not set. Contact submissions are disabled.');
    })
    .catch((error) => console.error('MongoDB connection failed:', error.name));
  app.listen(port, () => console.log(`Portfolio API listening on http://localhost:${port}`));
}