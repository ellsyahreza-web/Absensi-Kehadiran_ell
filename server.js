const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const moment = require('moment');
const path = require('path');
const crypto = require('crypto');
const QRCode = require('qrcode');

const app = express();
const port = process.env.PORT || 3000;
const databasePath = path.join(__dirname, 'database.sqlite');

// Setup Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET || 'attendance_secret_key_change_me',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));

// Initialize SQLite DB
const db = new sqlite3.Database(databasePath, (err) => {
    if (err) {
        console.error("Error opening database " + err.message);
    } else {
        console.log("Connected to the SQLite database.");
        db.run('PRAGMA foreign_keys = ON');
        
        // Create Users Table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            name TEXT,
            role TEXT,
            qr_token TEXT
        )`, (err) => {
            if (err) {
                console.error('Error creating users table:', err.message);
                return;
            }
            db.run('ALTER TABLE users ADD COLUMN qr_token TEXT', (alterError) => {
                if (alterError && !alterError.message.includes('duplicate column name')) {
                    console.error('Error adding QR column:', alterError.message);
                    return;
                }
                db.run('CREATE UNIQUE INDEX IF NOT EXISTS users_qr_token ON users (qr_token)', (indexError) => {
                    if (indexError) {
                        console.error('Error creating QR constraint:', indexError.message);
                        return;
                    }
                    db.run(`UPDATE users SET qr_token = lower(hex(randomblob(16))) WHERE qr_token IS NULL`, (tokenError) => {
                    if (tokenError) {
                        console.error('Error creating existing QR tokens:', tokenError.message);
                        return;
                    }
                    bcrypt.hash('admin123', 10, (hashError, hash) => {
                        if (hashError) return;
                        db.run(`INSERT OR IGNORE INTO users (username, password, name, role, qr_token) VALUES ('admin', ?, 'Administrator', 'admin', ?)`, [hash, crypto.randomUUID()]);
                    });
                    });
                });
            });
        });

        // Create Attendance Table
        db.run(`CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            subject_id INTEGER,
            date TEXT,
            clock_in TEXT,
            clock_out TEXT,
            status TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`, (attendanceError) => {
            if (attendanceError) {
                console.error('Error creating attendance table:', attendanceError.message);
                return;
            }
            db.run('ALTER TABLE attendance ADD COLUMN subject_id INTEGER', (alterError) => {
                if (alterError && !alterError.message.includes('duplicate column name')) {
                    console.error('Error adding subject column:', alterError.message);
                    return;
                }
                db.run('DROP INDEX IF EXISTS attendance_user_date');
                db.run('CREATE UNIQUE INDEX IF NOT EXISTS attendance_user_subject_date ON attendance (user_id, subject_id, date)', (indexError) => {
                if (indexError) {
                    console.error('Error creating attendance constraint:', indexError.message);
                }
                });
            });
        });

        db.run(`CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            code TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`);
    }
});

// Middleware to check authentication
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/login');
}

// Middleware to check admin role
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') {
        return next();
    }
    res.status(403).send("Access Denied");
}

// Routes
app.get('/', (req, res) => {
    if (req.session.user) {
        if (req.session.user.role === 'admin') {
            return res.redirect('/admin');
        } else {
            return res.redirect('/employee');
        }
    }
    res.redirect('/login');
});

// Auth Routes
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const username = (req.body.username || '').trim();
    const password = req.body.password || '';
    if (!username || !password) {
        return res.render('login', { error: 'Username dan password wajib diisi!' });
    }
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err || !user) {
            return res.render('login', { error: 'Username atau password salah!' });
        }
        bcrypt.compare(password, user.password, (err, result) => {
            if (!err && result) {
                req.session.user = user;
                if (user.role === 'admin') res.redirect('/admin');
                else res.redirect('/employee');
            } else {
                res.render('login', { error: 'Username atau password salah!' });
            }
        });
    });
});

app.get('/register', (req, res) => {
    res.render('register', { error: null, success: null, qrImage: null, name: '', username: '' });
});

app.post('/register', (req, res) => {
    const name = (req.body.name || '').trim();
    const username = (req.body.username || '').trim();
    const password = req.body.password || '';
    if (name.length < 2 || username.length < 3 || password.length < 6) {
        return res.render('register', {
            error: 'Nama minimal 2 karakter, username minimal 3 karakter, dan password minimal 6 karakter.',
            name,
            username
        });
    }
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.render('register', { error: 'Pendaftaran gagal. Silakan coba lagi.', name, username });
        }
        const qrToken = crypto.randomUUID();
        db.run(`INSERT INTO users (username, password, name, role, qr_token) VALUES (?, ?, ?, 'employee', ?)`, [username, hash, name, qrToken], function(err) {
            if (err) {
                return res.render('register', { error: 'Username sudah digunakan!', name, username });
            }
            res.render('register', {
                error: null,
                success: 'Pendaftaran berhasil. Silakan login untuk memindai QR sesi kehadiran.',
                qrImage: null,
                name,
                username
            });
        });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Employee Routes
app.get('/employee', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    const today = moment().format('YYYY-MM-DD');
    
    // Check if clocked in today
        db.all(`SELECT attendance.*, subjects.name AS subject_name
            FROM attendance LEFT JOIN subjects ON attendance.subject_id = subjects.id
            WHERE user_id = ? AND date = ?`, [userId, today], (err, todayAttendance) => {
        if (err) {
            return res.status(500).send('Gagal mengambil data kehadiran.');
        }
        // Get history
        db.all(`SELECT * FROM attendance WHERE user_id = ? ORDER BY date DESC`, [userId], (err, history) => {
            if (err) {
                return res.status(500).send('Gagal mengambil riwayat kehadiran.');
            }
            res.render('employee_dashboard', {
                user: req.session.user,
                todayAttendance,
                history: history,
                error: req.query.error || null
            });
        });
    });
});

app.post('/employee/clock-in', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    const today = moment().format('YYYY-MM-DD');
    const time = moment().format('HH:mm:ss');

    db.run(`INSERT INTO attendance (user_id, date, clock_in, status)
            SELECT ?, ?, ?, 'Hadir'
            WHERE NOT EXISTS (SELECT 1 FROM attendance WHERE user_id = ? AND date = ?)`,
        [userId, today, time, userId, today], (err) => {
        res.redirect(`/employee${err ? '?error=Gagal menyimpan absensi masuk.' : ''}`);
    });
});

app.post('/employee/clock-out', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    const today = moment().format('YYYY-MM-DD');
    const time = moment().format('HH:mm:ss');

    db.run(`UPDATE attendance SET clock_out = ?
            WHERE user_id = ? AND date = ? AND clock_in IS NOT NULL AND clock_out IS NULL`,
        [time, userId, today], function(err) {
        const message = err ? 'Gagal menyimpan absensi pulang.' : (this.changes ? '' : 'Belum ada absensi masuk atau sudah clock out.');
        res.redirect(`/employee${message ? `?error=${encodeURIComponent(message)}` : ''}`);
    });
});

app.post('/employee/scan-qr', isAuthenticated, (req, res) => {
    const scannedValue = (req.body.qrToken || '').trim();
    const qrMatch = scannedValue.match(/^attendance:\/\/subject\/(\d+)\/([^/]+)$/);
    if (!qrMatch) {
        return res.redirect('/employee?error=QR code tidak terbaca.');
    }
    const subjectId = Number.parseInt(qrMatch[1], 10);
    const qrToken = qrMatch[2];

    db.get(`SELECT id FROM users WHERE qr_token = ? AND role = 'admin'`, [qrToken], (err, admin) => {
        if (err || !admin) {
            return res.redirect('/employee?error=QR sesi kehadiran tidak valid.');
        }
        const userId = req.session.user.id;
        const today = moment().format('YYYY-MM-DD');
        const time = moment().format('HH:mm:ss');
        db.get(`SELECT * FROM attendance WHERE user_id = ? AND subject_id = ? AND date = ?`, [userId, subjectId, today], (attendanceError, attendance) => {
            if (attendanceError) {
                return res.redirect('/employee?error=Gagal membaca absensi.');
            }
            if (!attendance) {
                return db.run(`INSERT INTO attendance (user_id, subject_id, date, clock_in, status) VALUES (?, ?, ?, ?, 'Hadir')`, [userId, subjectId, today, time], (insertError) => {
                    const message = insertError ? 'Gagal menyimpan clock-in.' : 'Berhasil clock-in.';
                    res.redirect(`/employee?error=${encodeURIComponent(message)}`);
                });
            }
            if (!attendance.clock_out) {
                return db.run(`UPDATE attendance SET clock_out = ? WHERE id = ?`, [time, attendance.id], (updateError) => {
                    const message = updateError ? 'Gagal menyimpan clock-out.' : 'Berhasil clock-out.';
                    res.redirect(`/employee?error=${encodeURIComponent(message)}`);
                });
            }
            res.redirect(`/employee?error=${encodeURIComponent('Anda sudah selesai absen hari ini.')}`);
        });
    });
});

// Admin Routes
app.post('/admin/subjects', isAuthenticated, isAdmin, (req, res) => {
    const name = (req.body.name || '').trim();
    const code = (req.body.code || '').trim().toUpperCase();
    if (name.length < 2) {
        return res.redirect('/admin?error=Nama mata pelajaran wajib diisi.');
    }
    db.run(`INSERT INTO subjects (name, code) VALUES (?, ?)`, [name, code || null], (err) => {
        const message = err ? 'Mata pelajaran gagal ditambahkan atau kode sudah digunakan.' : 'Mata pelajaran berhasil ditambahkan.';
        res.redirect(`/admin?error=${encodeURIComponent(message)}`);
    });
});

app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    const stats = {
        totalStudents: 0,
        presentToday: 0,
        activeToday: 0
    };
        db.all(`SELECT attendance.*, users.name, subjects.name AS subject_name
            FROM attendance
            JOIN users ON attendance.user_id = users.id
            LEFT JOIN subjects ON attendance.subject_id = subjects.id
            ORDER BY date DESC, clock_in DESC`, (err, allAttendance) => {
        if (err) {
            return res.status(500).send('Gagal mengambil laporan kehadiran.');
        }
        db.all(`SELECT * FROM users WHERE role = 'employee'`, async (err, employees) => {
            if (err) {
                return res.status(500).send('Gagal mengambil data pegawai.');
            }
            db.all(`SELECT * FROM subjects ORDER BY name`, async (subjectError, subjects) => {
                if (subjectError) {
                    return res.status(500).send('Gagal mengambil mata pelajaran.');
                }
                const selectedSubjectId = Number.parseInt(req.query.subjectId, 10) || (subjects[0] && subjects[0].id);
                const selectedSubject = subjects.find((subject) => subject.id === selectedSubjectId) || null;
                const qrImage = selectedSubject
                    ? await QRCode.toDataURL(`attendance://subject/${selectedSubject.id}/${req.session.user.qr_token}`)
                    : null;
                const today = moment().format('YYYY-MM-DD');
                const todayAttendance = allAttendance.filter((record) => record.date === today);
                stats.totalStudents = employees.length;
                stats.presentToday = todayAttendance.filter((record) => record.clock_in).length;
                stats.activeToday = todayAttendance.filter((record) => record.clock_in && !record.clock_out).length;
                res.render('admin_dashboard', {
                    user: req.session.user,
                    allAttendance,
                    employees,
                    subjects,
                    selectedSubject,
                    qrImage,
                    stats,
                    error: req.query.error || null
                });
            });
        });
    });
});

app.post('/admin/delete-employee', isAuthenticated, isAdmin, (req, res) => {
    const id = Number.parseInt(req.body.id, 10);
    if (!Number.isInteger(id)) {
        return res.redirect('/admin?error=ID pegawai tidak valid.');
    }
    db.run(`DELETE FROM attendance WHERE user_id = ?`, [id], (attendanceError) => {
        if (attendanceError) {
            return res.redirect('/admin?error=Data absensi gagal dihapus.');
        }
        db.run(`DELETE FROM users WHERE id = ? AND role = 'employee'`, [id], (err) => {
            res.redirect(`/admin${err ? '?error=Pegawai gagal dihapus.' : ''}`);
        });
    });
});

// Start Server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
