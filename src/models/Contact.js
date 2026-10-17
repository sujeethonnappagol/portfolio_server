import mongoose from 'mongoose';

const contactSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  email: { type: String, required: true, trim: true, lowercase: true, maxlength: 254 },
  subject: { type: String, required: true, trim: true, maxlength: 120 },
  message: { type: String, required: true, trim: true, maxlength: 3000 },
  status: {
    type: String,
    enum: ['New', 'Read', 'Replied', 'Archived'],
    default: 'New',
    index: true,
  },
}, { timestamps: true });

export default mongoose.models.Contact || mongoose.model('Contact', contactSchema);