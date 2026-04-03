const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors()); // السماح للإضافة بالاتصال

// ==========================================
// 🛡️ إعدادات الأمان السريــة (Variables)
// ==========================================
// في الإنتاج، يجب وضع هذه القيم في إعدادات Railway (Environment Variables)
const SERVER_SECRET = process.env.SERVER_SECRET || "Mouad_Super_Secret_Key_2026";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "mouad123";

// هذا هو "المفتاح" الذي نرسله للإضافة لكي يفك تشفير روابطه ويعمل
// بدونه، الإضافة عبارة عن كود ميت لا فائدة منه
const BOT_DECRYPTION_KEY = process.env.BOT_DECRYPTION_KEY || "NINJA_V1_MASTER_DECRYPT_KEY_998877";

// قاعدة البيانات (في الذاكرة - يمكن ربطها بـ MongoDB لاحقاً)
let database = {};

// ==========================================
// 🤖 مسار فحص الإضافة (البوت) - صرامة تامة
// ==========================================
app.post('/api/auth/verify', (req, res) => {
    try {
        // الإضافة ترسل: المعرف، الوقت، التوقيع، والتوكن الحالي
        const { deviceId, timestamp, signature, currentToken } = req.body;

        // 1. الحماية من إعادة استخدام الطلبات (Replay Attacks)
        const now = Date.now();
        if (Math.abs(now - timestamp) > 60000) { // الطلب صالح لدقيقة واحدة
            return res.status(403).json({ status: "Error", message: "Expired request timeout." });
        }

        // 2. التحقق من التوقيع (التأكد من أن الطلب قادم من إضافتك وليس من Postman)
        const expectedSignature = crypto
            .createHmac('sha256', SERVER_SECRET)
            .update(`${deviceId}:${timestamp}`)
            .digest('hex');

        if (signature !== expectedSignature) {
            console.log(`[تحذير أمني] محاولة تزوير طلب من: ${deviceId}`);
            return res.status(403).json({ status: "Error", message: "Invalid Signature." });
        }

        // 3. جلب الجهاز من قاعدة البيانات
        let device = database[deviceId];
        
        // إذا كان الجهاز جديداً تماماً (أول مرة يفتح الإضافة)
        if (!device) {
            database[deviceId] = { 
                status: "Pending", 
                expectedToken: "INIT", // التوكن المبدئي
                lastSeen: new Date().toISOString() 
            };
            return res.json({ status: "Pending", message: "Waiting for admin approval." });
        }

        // تحديث آخر ظهور
        device.lastSeen = new Date().toISOString();

        // 4. أوامر "التدمير الذاتي" (Self-Destruct Triggers)
        if (device.status === "Banned" || device.status === "Expired") {
            // هذه الحالة ستلتقطها الإضافة وتقوم بتفعيل كود chrome.management.uninstallSelf()
            return res.json({ status: device.status, message: "Access permanently revoked." });
        }

        if (device.status === "Pending" || device.status === "Rejected") {
            return res.json({ status: device.status, message: "Access not granted yet." });
        }

        // 5. 🔴 نظام اكتشاف نسخ VMware (Rolling Token) 🔴
        if (device.status === "Active") {
            
            // التحقق مما إذا كان التوكن المرسل يطابق التوكن المتوقع في السيرفر
            if (currentToken !== device.expectedToken) {
                console.log(`🚨 [خطر] تم اكتشاف نسخة مقلدة (VMware) للجهاز: ${deviceId}`);
                
                // تدمير البوت فوراً وحظره نهائياً
                device.status = "Banned";
                device.banReason = "Clone/VMware Detected";
                
                return res.json({ 
                    status: "Banned", 
                    message: "Security Violation: Cloning detected. You are banned." 
                });
            }

            // إذا كان التوكن صحيحاً، نقوم بتوليد توكن جديد للطلب القادم
            const nextToken = crypto.randomBytes(16).toString('hex');
            device.expectedToken = nextToken; // السيرفر الآن ينتظر هذا التوكن في المرة القادمة

            // 6. الموافقة وإرسال "مفتاح الحياة" للإضافة
            return res.json({
                status: "Active",
                nextToken: nextToken, // يجب على الإضافة حفظ هذا التوكن وإرساله في الطلب القادم
                decryptionKey: BOT_DECRYPTION_KEY // المفتاح الذي سيشغل كود البوت
            });
        }

    } catch (error) {
        return res.status(500).json({ status: "Error", message: "Internal Server Error" });
    }
});

// ==========================================
// 👑 مسارات لوحة التحكم (Admin Panel)
// ==========================================

// عرض الواجهة
app.get('/AdminMouad', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// التحقق من الإدارة
const checkAdminAuth = (req, res, next) => {
    if (req.headers['x-admin-pass'] === ADMIN_PASSWORD) {
        next();
    } else {
        res.status(401).json({ error: "Unauthorized" });
    }
};

// جلب البيانات
app.get('/api/admin/devices', checkAdminAuth, (req, res) => {
    res.json(database);
});

// التحكم في الأجهزة
app.post('/api/admin/action', checkAdminAuth, (req, res) => {
    const { deviceId, action } = req.body;
    
    if (!database[deviceId]) return res.status(404).json({ error: "Device not found" });

    if (action === "Delete") {
        delete database[deviceId];
    } else {
        database[deviceId].status = action;
        // إعادة تعيين التوكن عند التفعيل من جديد
        if (action === "Active") {
            database[deviceId].expectedToken = "INIT";
        }
    }

    res.json({ success: true, database });
});

const PORT = process.env.PORT || 3000;
// أضفنا '0.0.0.0' لكي يعمل بشكل صحيح على Railway
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Ninja Server] Running strictly on port ${PORT}`);
});
