import mongoose from 'mongoose';

const assetSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  contentType: { type: String, required: true },
  data: { type: Buffer, required: true },
  updatedAt: { type: Date, default: Date.now },
}, { _id: false });

const portfolioContentSchema = new mongoose.Schema({
  _id: { type: String, default: 'site' },
  content: { type: mongoose.Schema.Types.Mixed, default: {} },
  resume: { type: assetSchema, default: undefined },
  portrait: { type: assetSchema, default: undefined },
}, { timestamps: true, versionKey: false });

export default mongoose.models.PortfolioContent
  || mongoose.model('PortfolioContent', portfolioContentSchema);
