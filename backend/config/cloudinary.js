const cloudinary = require('cloudinary').v2;
const { Readable } = require('stream');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

dotenv.config();

const cloud_name = process.env.CLOUDINARY_CLOUD_NAME || 'r6vovvet';
const api_key = process.env.CLOUDINARY_API_KEY || '168714678711119';
const api_secret = process.env.CLOUDINARY_API_SECRET || 'jbKogCLVFjo-5fZwDdUt23h6OeI';

cloudinary.config({
  cloud_name,
  api_key,
  api_secret,
  secure: true
});

function createResultObject(result) {
  const secureUrl = result.secure_url || result.url;
  return {
    success: true,
    url: secureUrl,
    secure_url: secureUrl,
    key: result.public_id,
    publicId: result.public_id,
    format: result.format,
    resource_type: result.resource_type,
    category: result.resource_type === 'image' ? 'image' : (result.resource_type === 'video' ? 'video' : 'document'),
    bytes: result.bytes,
    width: result.width,
    height: result.height,
    toString() { return secureUrl; },
    [Symbol.toPrimitive]() { return secureUrl; }
  };
}

/**
 * Uploads an image, video, or document to Cloudinary.
 * Supports Buffers (multer memoryStorage), base64 data strings, or local file paths.
 * Returns a result object that coerces to the secure_url string when cast to string,
 * guaranteeing 100% backward compatibility for legacy callers expecting a string URL.
 */
async function uploadToCloudinary(fileBufferOrPath, folder = 'connect_uploads', filenameHint = 'upload.jpg') {
  if (!fileBufferOrPath) {
    throw new Error('No file payload provided for Cloudinary upload.');
  }

  // If already an uploaded Cloudinary URL, return as-is
  if (typeof fileBufferOrPath === 'string') {
    const trimmed = fileBufferOrPath.trim();
    if (trimmed.startsWith('https://res.cloudinary.com/') || trimmed.startsWith('http://res.cloudinary.com/')) {
      return trimmed;
    }
  }

  const safeFolder = String(folder || 'connect_uploads').replace(/[^a-zA-Z0-9_\-\/]/g, '_');
  const baseName = path.basename(filenameHint || 'file').replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '_');
  const publicId = `${baseName}_${Date.now()}`;

  const uploadOptions = {
    folder: safeFolder,
    public_id: publicId,
    resource_type: 'auto', // Automatically handles images, videos, audio, and documents (PDF, doc, etc.)
    use_filename: true,
    unique_filename: true,
    overwrite: false
  };

  return new Promise((resolve, reject) => {
    // 1. If payload is a Buffer (e.g. from multer memoryStorage)
    if (Buffer.isBuffer(fileBufferOrPath)) {
      const uploadStream = cloudinary.uploader.upload_stream(uploadOptions, (error, result) => {
        if (error) {
          console.error('[Cloudinary Upload Stream Error]:', error);
          return reject(new Error(`Cloudinary upload failed: ${error.message || error}`));
        }
        resolve(createResultObject(result));
      });
      Readable.from(fileBufferOrPath).pipe(uploadStream);
      return;
    }

    // 2. If payload is a string (base64 data URI or local file path)
    if (typeof fileBufferOrPath === 'string') {
      const trimmed = fileBufferOrPath.trim();
      if (trimmed.startsWith('data:') || fs.existsSync(trimmed)) {
        cloudinary.uploader.upload(trimmed, uploadOptions, (error, result) => {
          if (error) {
            console.error('[Cloudinary Upload Error]:', error);
            return reject(new Error(`Cloudinary upload failed: ${error.message || error}`));
          }
          resolve(createResultObject(result));
        });
        return;
      }
    }

    reject(new Error('Invalid file format. Cloudinary upload requires a Buffer, valid file path, or base64 data string.'));
  });
}

module.exports = {
  cloudinary,
  uploadToCloudinary
};
