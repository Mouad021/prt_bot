const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
// السماح للإضافة بالاتصال بالسيرفر
app.use(cors());

// --- إعدادات الأمان (يجب وضعها في متغيرات البيئة في Railway لاحقاً) ---
const SERVER_SECRET = process.env.SERVER_SECRET || "Mouad_Super_Secret_Key_2026";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "mouad123"; // كلمة مرور لوحة التحكم

// قاعدة بيانات مؤقتة (في الذاكرة) - *ملاحظة: في الإنتاج الحقيقي يفضل استخدام MongoDB*
let database = {};

// ==========================================
// 1. مسارات الإضافة (البوت) - صرامة تامة
// ==========================================
app.post('/api/auth/verify', (req, res) => {
    try {
        const { deviceId, timestamp, signature } = req.body;

        const now = Date.now();
        if (Math.abs(now - timestamp) > 60000) {
            return res.status(403).json({ error: "Expired request" });
        }

        const expectedSignature = crypto
            .createHmac('sha256', SERVER_SECRET)
            .update(`${deviceId}:${timestamp}`)
            .digest('hex');

        if (signature !== expectedSignature) {
            return res.status(403).json({ error: "Invalid signature! Hacker detected." });
        }

        let device = database[deviceId];
        
        if (!device) {
            // تسجيل جهاز جديد كـ Pending (ينتظر موافقتك)
            database[deviceId] = { status: "Pending", lastSeen: new Date().toISOString() };
            return res.status(403).json({ status: "Pending", message: "Waiting for admin approval" });
        }

        // تحديث آخر ظهور
        device.lastSeen = new Date().toISOString();

        if (device.status === "Banned" || device.status === "Rejected") {
            return res.status(403).json({ status: device.status, message: "Access denied." });
        }

        if (device.status === "Active") {
            const sessionToken = jwt.sign({ deviceId: deviceId }, SERVER_SECRET, { expiresIn: '1h' });
            return res.json({
                status: "Active",
                token: sessionToken,
                botKey: "KEY_REQUIRED_FOR_BOT_FUNCTIONS" // بدون هذا لا تعمل الإضافة
            });
        }

    } catch (error) {
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

// ==========================================
// 2. مسارات لوحة التحكم (AdminMouad)
// ==========================================

// عرض واجهة لوحة التحكم
app.get('/AdminMouad', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// ميدل وير للتحقق من كلمة مرور الأدمن
const checkAdminAuth = (req, res, next) => {
    const pass = req.headers['x-admin-pass'];
    if (pass === ADMIN_PASSWORD) {
        next();
    } else {
        res.status(401).json({ error: "Unauthorized access" });
    }
};

// جلب قائمة البوتات
app.get('/api/admin/devices', checkAdminAuth, (req, res) => {
    res.json(database);
});

// تغيير حالة البوت (قبول، رفض، حظر)
app.post('/api/admin/action', checkAdminAuth, (req, res) => {
    const { deviceId, action } = req.body;
    
    if (!database[deviceId]) {
        return res.status(404).json({ error: "Device not found" });
    }

    // action: "Active", "Pending", "Rejected", "Banned", "Delete"
    if (action === "Delete") {
        delete database[deviceId];
    } else {
        database[deviceId].status = action;
    }

    res.json({ success: true, database });
});

// تشغيل السيرفر
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Admin Panel: http://localhost:${PORT}/AdminMouad`);
});
