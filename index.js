"use strict";

const {
  createHash,
  createHmac,
  randomInt,
  timingSafeEqual,
} = require("node:crypto");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, Timestamp } = require("firebase-admin/firestore");
const { defineSecret } = require("firebase-functions/params");
const { HttpsError, onCall } = require("firebase-functions/v2/https");

initializeApp();

const db = getFirestore();
const REGION = "asia-southeast1";
const OTP_TTL_MS = 10 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const RATE_WINDOW_MS = 60 * 60 * 1000;
const MAX_EMAIL_SENDS_PER_HOUR = 5;
const MAX_IP_SENDS_PER_HOUR = 10;
const MAX_VERIFY_ATTEMPTS = 5;

const resendApiKey = defineSecret("RESEND_API_KEY");
const resendFromEmail = defineSecret("RESEND_FROM_EMAIL");
const otpHashSecret = defineSecret("OTP_HASH_SECRET");

function normalizeEmail(value) {
  if (typeof value !== "string") {
    throw new HttpsError("invalid-argument", "Email peminjam wajib diisi.");
  }

  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new HttpsError(
      "invalid-argument",
      "Format email peminjam tidak valid.",
    );
  }
  return email;
}

function emailHash(email) {
  return createHash("sha256").update(email).digest("hex");
}

function challengeRef(email) {
  return db.collection("emailOtpChallenges").doc(emailHash(email));
}

function otpHash(email, code) {
  return createHmac("sha256", otpHashSecret.value())
    .update(`${email}|${code}`)
    .digest("hex");
}

function sendRateRef(kind, value) {
  return db.collection("emailOtpRateLimits").doc(`${kind}_${value}`);
}

function nextRateWindow(snapshot, now, limit, subject) {
  const previous = snapshot.exists ? snapshot.data() : {};
  const activeWindow =
    typeof previous.windowStartedAt === "number" &&
    now - previous.windowStartedAt < RATE_WINDOW_MS;
  const count = activeWindow ? previous.count : 0;
  if (count >= limit) {
    throw new HttpsError(
      "resource-exhausted",
      `Batas pengiriman OTP ${subject} tercapai. Coba lagi dalam satu jam.`,
    );
  }
  return {
    windowStartedAt: activeWindow ? previous.windowStartedAt : now,
    count: count + 1,
  };
}

function matchesHash(expectedHex, actualHex) {
  if (
    typeof expectedHex !== "string" ||
    !/^[a-f0-9]{64}$/.test(expectedHex) ||
    !/^[a-f0-9]{64}$/.test(actualHex)
  ) {
    return false;
  }
  return timingSafeEqual(
    Buffer.from(expectedHex, "hex"),
    Buffer.from(actualHex, "hex"),
  );
}

exports.sendBorrowerEmailOtp = onCall(
  {
    region: REGION,
    secrets: [resendApiKey, resendFromEmail, otpHashSecret],
    maxInstances: 5,
  },
  async (request) => {
    const email = normalizeEmail(request.data && request.data.email);
    const ip = request.rawRequest.ip;
    if (!ip) {
      throw new HttpsError(
        "failed-precondition",
        "Alamat jaringan tidak tersedia. Muat ulang halaman dan coba lagi.",
      );
    }
    const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
    const now = Date.now();
    const ref = challengeRef(email);
    const emailRateRef = sendRateRef("email", emailHash(email));
    const ipHash = createHmac("sha256", otpHashSecret.value())
      .update(ip)
      .digest("hex");
    const ipRateRef = sendRateRef("ip", ipHash);

    await db.runTransaction(async (transaction) => {
      const [snapshot, emailRateSnapshot, ipRateSnapshot] = await Promise.all([
        transaction.get(ref),
        transaction.get(emailRateRef),
        transaction.get(ipRateRef),
      ]);
      const lastSentAt = snapshot.exists ? snapshot.data().lastSentAt : 0;
      if (now - lastSentAt < RESEND_COOLDOWN_MS) {
        throw new HttpsError(
          "resource-exhausted",
          "Tunggu satu menit sebelum meminta kode OTP lagi.",
        );
      }

      const emailRate = nextRateWindow(
        emailRateSnapshot,
        now,
        MAX_EMAIL_SENDS_PER_HOUR,
        "untuk alamat email ini",
      );
      const ipRate = nextRateWindow(
        ipRateSnapshot,
        now,
        MAX_IP_SENDS_PER_HOUR,
        "dari jaringan ini",
      );

      transaction.set(ref, {
        emailHash: emailHash(email),
        codeHash: otpHash(email, code),
        attempts: 0,
        lastSentAt: now,
        expiresAt: Timestamp.fromMillis(now + OTP_TTL_MS),
        verifiedAt: null,
      });
      transaction.set(emailRateRef, emailRate);
      transaction.set(ipRateRef, ipRate);
    });

    try {
      const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${resendApiKey.value()}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: resendFromEmail.value(),
          to: [email],
          subject: "Kode verifikasi email Rak Ceria",
          text: `Kode OTP email Rak Ceria Anda adalah ${code}. Kode berlaku selama 10 menit. Jangan bagikan kode ini kepada siapa pun.`,
        }),
      });

      if (!response.ok) {
        console.error("Resend rejected OTP email:", response.status);
        throw new HttpsError(
          "unavailable",
          "Email OTP gagal dikirim. Periksa konfigurasi layanan email.",
        );
      }
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }
      console.error("Resend request failed:", error);
      throw new HttpsError(
        "unavailable",
        "Email OTP gagal dikirim. Periksa koneksi dan coba lagi.",
      );
    }

    return { sent: true };
  },
);

exports.verifyBorrowerEmailOtp = onCall(
  {
    region: REGION,
    secrets: [otpHashSecret],
    maxInstances: 5,
  },
  async (request) => {
    const email = normalizeEmail(request.data && request.data.email);
    const code =
      request.data && typeof request.data.code === "string"
        ? request.data.code.trim()
        : "";
    if (!/^\d{6}$/.test(code)) {
      throw new HttpsError("invalid-argument", "Masukkan kode OTP 6 digit.");
    }

    const ref = challengeRef(email);
    const submittedHash = otpHash(email, code);
    const now = Date.now();

    const verification = await db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(ref);
      if (!snapshot.exists) {
        throw new HttpsError(
          "failed-precondition",
          "Minta kode OTP terlebih dahulu.",
        );
      }

      const challenge = snapshot.data();
      if (challenge.verifiedAt) {
        throw new HttpsError(
          "failed-precondition",
          "Email ini sudah diverifikasi dengan kode OTP.",
        );
      }
      if (challenge.expiresAt.toMillis() <= now) {
        throw new HttpsError(
          "deadline-exceeded",
          "Kode OTP sudah kedaluwarsa. Minta kode baru.",
        );
      }
      if (challenge.attempts >= MAX_VERIFY_ATTEMPTS) {
        throw new HttpsError(
          "resource-exhausted",
          "Batas percobaan tercapai. Minta kode OTP baru.",
        );
      }

      const attempts = challenge.attempts + 1;
      const isCorrect = matchesHash(challenge.codeHash, submittedHash);
      transaction.update(ref, {
        attempts,
        ...(isCorrect ? { codeHash: null, verifiedAt: now } : {}),
      });
      return { isCorrect, attempts, verifiedAt: now };
    });

    if (!verification.isCorrect) {
      const remaining = MAX_VERIFY_ATTEMPTS - verification.attempts;
      throw new HttpsError(
        "permission-denied",
        remaining > 0
          ? `Kode OTP salah. Sisa percobaan: ${remaining}.`
          : "Kode OTP salah. Batas percobaan tercapai; minta kode baru.",
      );
    }

    return { verified: true, verifiedAt: verification.verifiedAt };
  },
);
