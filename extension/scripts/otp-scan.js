const video = document.getElementById('scan-video');
const statusEl = document.getElementById('scan-status');
const secretOutput = document.getElementById('secret-output');
const cancelButton = document.getElementById('scan-cancel');
const copyButton = document.getElementById('scan-copy');

const detector =
  typeof window !== 'undefined' && 'BarcodeDetector' in window
    ? new window.BarcodeDetector({ formats: ['qr_code'] })
    : null;

const scanCanvas = document.createElement('canvas');
const scanCtx = scanCanvas.getContext('2d');

let captureStream = null;
let scanLoopId = null;
let secretCaptured = null;

function setStatus(message, { error = false } = {}) {
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message ?? '';
  statusEl.classList.toggle('error', Boolean(error));
}

function stopScanLoop() {
  if (scanLoopId) {
    cancelAnimationFrame(scanLoopId);
    scanLoopId = null;
  }
}

function stopCapture() {
  stopScanLoop();
  if (video) {
    video.pause();
    video.srcObject = null;
  }
  if (captureStream) {
    captureStream.getTracks().forEach((track) => track.stop());
    captureStream = null;
  }
}

function parseOtpSecret(uri) {
  if (!uri) {
    return null;
  }

  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== 'otpauth:') {
      return null;
    }

    const secret = parsed.searchParams.get('secret');
    if (!secret) {
      return null;
    }

    return secret.replace(/\s+/g, '').toUpperCase();
  } catch {
    return null;
  }
}

async function scanFrame() {
  if (!detector || secretCaptured) {
    return;
  }

  if (video?.readyState < HTMLMediaElement.HAVE_ENOUGH_DATA) {
    scanLoopId = requestAnimationFrame(scanFrame);
    return;
  }

  try {
    const width = video.videoWidth;
    const height = video.videoHeight;
    if (width && height) {
      scanCanvas.width = width;
      scanCanvas.height = height;
      scanCtx.drawImage(video, 0, 0, width, height);
    }
    const results = await detector.detect(scanCanvas);
    if (results.length) {
      const secret = parseOtpSecret(results[0].rawValue);
      if (secret) {
        secretCaptured = secret;
        secretOutput.textContent = secret;
        secretOutput.hidden = false;
        copyButton.hidden = false;
        setStatus('OTP secret detected', { error: false });
        await chrome.storage.local.set({ otpScanResult: secret });
        try {
          await navigator.clipboard.writeText(secret);
        } catch {
          // ignore
        }
        stopCapture();
        window.close();
        return;
      }
      setStatus('QR code detected but no OTP data was found', { error: true });
    }
  } catch (error) {
    setStatus('Unable to read the QR code', { error: true });
    stopCapture();
    return;
  }

  scanLoopId = requestAnimationFrame(scanFrame);
}

async function startCapture() {
  if (!navigator.mediaDevices?.getDisplayMedia) {
    setStatus('Screen capture is not available in this browser', { error: true });
    return;
  }

  if (!detector) {
    setStatus('QR scanning requires a compatible browser (BarcodeDetector)', { error: true });
    return;
  }

  try {
    captureStream = await navigator.mediaDevices.getDisplayMedia({
      video: { cursor: 'never' },
    });
    if (video) {
      video.srcObject = captureStream;
      await video.play();
    }
    setStatus('Scanning... select the window with the QR code.');
    scanLoopId = requestAnimationFrame(scanFrame);
  } catch (error) {
    setStatus('Unable to capture the screen', { error: true });
  }
}

function handleClose() {
  stopCapture();
  window.close();
}

cancelButton?.addEventListener('click', handleClose);
window.addEventListener('beforeunload', stopCapture);

copyButton?.addEventListener('click', async () => {
  if (!secretCaptured) {
    return;
  }

  try {
    await navigator.clipboard.writeText(secretCaptured);
    setStatus('Secret copied to clipboard');
  } catch {
    setStatus('Unable to copy secret', { error: true });
  }
});

startCapture();
