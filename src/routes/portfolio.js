import { Router } from 'express';
import mongoose from 'mongoose';
import PortfolioContent from '../models/PortfolioContent.js';
import { portfolioDefaults } from '../data/portfolioDefaults.js';

const router = Router();

router.get('/', async (_request, response, next) => {
  try {
    const saved = mongoose.connection.readyState === 1
      ? await PortfolioContent.findById('site').lean()
      : null;
    response.set('Cache-Control', 'no-store');
    return response.json({
      ...portfolioDefaults,
      ...(saved?.content || {}),
      resumeUrl: saved?.resume ? '/api/portfolio/resume' : '/assets/sujeet-resume.pdf',
      portraitUrl: saved?.portrait ? '/api/portfolio/portrait' : '/assets/sujeet-portrait.png',
    });
  } catch (error) {
    return next(error);
  }
});

for (const assetName of ['resume', 'portrait']) {
  router.get(`/${assetName}`, async (_request, response, next) => {
    try {
      const saved = mongoose.connection.readyState === 1
        ? await PortfolioContent.findById('site').select(assetName).lean()
        : null;
      const asset = saved?.[assetName];
      if (!asset?.data) return response.status(404).json({ error: 'File not found.' });
      response.set({
        'Content-Type': asset.contentType,
        'Content-Length': asset.data.length,
        'Cache-Control': 'public, max-age=300',
        'X-Content-Type-Options': 'nosniff',
      });
      if (assetName === 'resume') {
        const filename = asset.filename.replace(/["\\\r\n]/g, '_');
        response.set('Content-Disposition', `inline; filename="${filename}"`);
      }
      return response.send(asset.data);
    } catch (error) {
      return next(error);
    }
  });
}

export default router;
