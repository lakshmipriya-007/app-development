// DEVELOPMENT ONLY - wipes all data and inserts demo accounts and complaints.
if (process.env.NODE_ENV === 'production') { console.error('Refusing to seed in production.'); process.exit(1); }
const bcrypt = require('bcrypt');
const db = require('./db');

db.exec('DELETE FROM Notifications; DELETE FROM Complaint_Status_History; DELETE FROM Complaints; DELETE FROM Users; DELETE FROM Admins; DELETE FROM sqlite_sequence;');

const h = p => bcrypt.hashSync(p, 10);
db.prepare('INSERT INTO Admins(name,username,email,password_hash) VALUES(?,?,?,?)').run('Campus Administrator', 'admin', 'admin@campus.edu', h('Admin@123'));
const addUser = db.prepare('INSERT INTO Users(full_name,register_no,email,department,year,password_hash) VALUES(?,?,?,?,?,?)');
const priya = Number(addUser.run('Priya Sharma', 'REG2023CS001', 'priya@student.edu', 'Computer Science', 3, h('Student@123')).lastInsertRowid);
const arjun = Number(addUser.run('Arjun Kumar', 'REG2023ME014', 'arjun@student.edu', 'Mechanical', 2, h('Student@123')).lastInsertRowid);

const daysAgo = n => `datetime('now','-${n} days')`;
const add = (uid, title, cat, desc, loc, block, room, priority, status, ago, steps) => {
  const id = Number(db.prepare(`INSERT INTO Complaints(user_id,title,category,description,location,block,room,priority,status,admin_remarks,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,${daysAgo(ago)},${daysAgo(Math.max(ago - steps.length, 0))})`)
    .run(uid, title, cat, desc, loc, block, room, priority, status, steps.length ? steps[steps.length - 1][1] || null : null).lastInsertRowid);
  db.prepare('UPDATE Complaints SET complaint_code=? WHERE id=?').run(`CC-${new Date().getFullYear()}-${String(id).padStart(4, '0')}`, id);
  const code = db.prepare('SELECT complaint_code c FROM Complaints WHERE id=?').get(id).c;
  const hist = db.prepare(`INSERT INTO Complaint_Status_History(complaint_id,status,remarks,changed_by,created_at) VALUES(?,?,?,?,${'datetime(\'now\',?)'})`);
  hist.run(id, 'Pending', 'Complaint submitted', 'Student', `-${ago} days`);
  const note = db.prepare('INSERT INTO Notifications(user_id,complaint_id,message,is_read,created_at) VALUES(?,?,?,?,datetime(\'now\',?))');
  note.run(uid, id, `Your complaint ${code} was submitted successfully.`, 1, `-${ago} days`);
  steps.forEach(([st, remark], i) => {
    const when = `-${Math.max(ago - i - 1, 0)} days`;
    hist.run(id, st, remark || null, 'Campus Administrator', when);
    note.run(uid, id, st === 'Resolved' ? `Your complaint ${code} has been resolved.` : st === 'Under Review' ? `Your complaint ${code} is now being reviewed by the administrator.` : `The status of complaint ${code} changed to ${st}.`, i < steps.length - 1 ? 1 : 0, when);
  });
};

add(priya, 'Projector not working in Room 204', 'Classroom Maintenance', 'The ceiling projector in Room 204 shows a blank screen and the HDMI port looks loose. Classes are being disrupted.', 'Main Academic Building', 'Block A', '204', 'High', 'In Progress', 4, [['Under Review', 'Technician has been informed.'], ['In Progress', 'Replacement HDMI cable ordered.']]);
add(priya, 'Water cooler leaking near library', 'Water Supply', 'The water cooler on the ground floor near the library entrance has been leaking for two days and the floor is slippery.', 'Library', 'Block C', 'Ground floor', 'Medium', 'Pending', 1, []);
add(priya, 'Wi-Fi extremely slow in computer lab', 'Internet and Wi-Fi', 'Wi-Fi speed in the CS lab drops below 1 Mbps during afternoon sessions, making online coding practice impossible.', 'CS Department', 'Block B', 'Lab 3', 'Medium', 'Resolved', 9, [['Under Review', 'Network team checking the access point.'], ['In Progress', 'Access point being replaced.'], ['Resolved', 'New access point installed and tested.']]);
add(arjun, 'Broken fan in hostel room 112', 'Hostel Issues', 'The ceiling fan in room 112 stopped working and makes a grinding noise before shutting off.', 'Boys Hostel', 'Hostel 1', '112', 'Urgent', 'Under Review', 2, [['Under Review', 'Warden has been notified.']]);
add(arjun, 'Washroom not cleaned on second floor', 'Washroom Cleanliness', 'The second floor washroom in the mechanical block has not been cleaned for three days.', 'Mechanical Block', 'Block D', 'Floor 2', 'Low', 'Rejected', 6, [['Rejected', 'Duplicate of an existing complaint already being handled.']]);
add(arjun, 'Flickering lights in workshop', 'Electrical Problems', 'Tube lights in the main workshop flicker constantly, which is unsafe while operating machines.', 'Workshop', 'Block D', 'Main hall', 'High', 'Pending', 0, []);

console.log('\nSeed complete.\n  Admin:   admin / Admin@123\n  Student: REG2023CS001 (priya@student.edu) / Student@123\n  Student: REG2023ME014 (arjun@student.edu) / Student@123\n');
