import express from 'express';
import cors from 'cors';
import mysql from 'mysql2'; // Use mysql2
import bcrypt from 'bcrypt';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import multer from 'multer';
import path, { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path'
import dotenv from 'dotenv';
import fs from 'fs';
import https from 'https';
import jwt from 'jsonwebtoken';
import cron from 'node-cron';

dotenv.config();
const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const router = express.Router();
const options = {
  key: fs.readFileSync('/etc/letsencrypt/live/virtual-max.com/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/virtual-max.com/fullchain.pem')
};


app.use('/uploads', express.static(join(__dirname, 'uploads')));
app.use(bodyParser.json());

app.use(cors({
origin: 'https://virtual-max.com',
methods: ['GET','HEAD','PUT','PATCH','POST','DELETE'],  

credentials: true,

}));
app.use(cookieParser());
app.use(express.json());
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 699900000 } 

}));

const PORT=8083;
const con = mysql.createConnection({
    host: '127.0.0.1',
    user: 'user',
    password: 'password',
    database: 'database',
});

con.connect(function(err){
    if (err) {
        console.error('Error in connection:', err); 
    } else {
        console.log('Connected');
    }
}
);


cron.schedule('55 23 * * *', () => {
    console.log('Starting cron job at midnight...');

    // Begin transaction for bonus functionality
    con.beginTransaction(err => {
        if (err) {
            console.error('Error starting transaction:', err);
            return;
        }

        // Delete records from user_product_clicks where last_clicked is before or on today's date
        const deleteOldProductClicksQuery = `
            DELETE FROM user_product_clicks
            WHERE DATE(last_clicked) <= CURDATE();
        `;
        console.log('Starting deletion of old user_product_clicks...');
        con.query(deleteOldProductClicksQuery, (err, result) => {
            if (err) {
                return con.rollback(() => {
                    console.error('Error deleting old user_product_clicks:', err);
                });
            }
            console.log('Deleted old records from user_product_clicks:', result.affectedRows);

            // Check if admin clicked the button already
            const adminId = 1;
            const checkClickQuery = `
                SELECT 1 FROM bonus_button_clicks 
                WHERE admin_id = ? AND DATE(clicked_at) = CURDATE()
            `;
            con.query(checkClickQuery, [adminId], (err, results) => {
                if (err) {
                    return con.rollback(() => {
                        console.error('Error checking bonus button click:', err);
                    });
                }

                if (results.length > 0) {
                    console.log('Bonus already given today.');
                    return con.rollback(() => {}); // No changes needed; rollback and exit
                }

                // Log bonus button click
                const logButtonClickQuery = `
                    INSERT INTO bonus_button_clicks (admin_id) VALUES (?)
                `;
                con.query(logButtonClickQuery, [adminId], err => {
                    if (err) {
                        return con.rollback(() => {
                            console.error('Error logging bonus button click:', err);
                        });
                    }

                    // Update user balances based on the bonus logic
                    const bonusQuery = `
                        UPDATE users u
                        JOIN (
                            SELECT
                                u.id AS user_id,
                                bs.reward
                            FROM
                                users u
                            JOIN (
                                SELECT 
                                    u2.refer_by,
                                    COUNT(u2.id) AS referred_count
                                FROM 
                                    users u2
                                WHERE 
                                    u2.approved_at IS NOT NULL 
                                    AND DATE(u2.approved_at) = CURDATE()
                                GROUP BY 
                                    u2.refer_by
                            ) AS referrals ON u.id = referrals.refer_by
                            JOIN bonus_settings bs 
                                ON referrals.referred_count >= bs.need_refferer
                                AND NOT EXISTS (
                                    SELECT 1
                                    FROM bonus_settings bs2
                                    WHERE bs2.need_refferer > bs.need_refferer
                                    AND referrals.referred_count >= bs2.need_refferer
                                )
                        ) AS reward_data ON u.id = reward_data.user_id
                        SET u.balance = COALESCE(u.balance, 0) + reward_data.reward;
                    `;

                    con.query(bonusQuery, (err, result) => {
                        if (err) {
                            return con.rollback(() => {
                                console.error('Error giving bonus:', err);
                            });
                        }
                        console.log('Bonus distributed successfully.');

                        // Commit transaction
                        con.commit(errCommit => {
                            if (errCommit) {
                                return con.rollback(() => {
                                    console.error('Error committing transaction:', errCommit);
                                });
                            }
                            console.log('Cron job executed successfully.');
                        });
                    });
                });
            });
        });
    });
});


function keepConnectionAlive() {
  con.query('SELECT 1', (err) => {
    if (err) {
      console.error('Error pinging the database:', err);
    } else {
      console.log('Database connection alive');
    }
  });
}

// Set interval to ping the database every hour (3600000 milliseconds = 1 hour)
setInterval(keepConnectionAlive, 60000);
const storage = multer.diskStorage({
    destination: './uploads/', // Store files in 'uploads' directory
    filename: (req, file, cb) => {
      cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname)); // Ensure unique filenames
    }
  });
  
  const upload = multer({ storage: storage });
  
  // Ensure the 'uploads' folder exists
  if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
  }
  

  app.get('/', (req, res) => {
    res.send(`
      Welcome to the server!`);

});




app.post('/login', (req, res) => {
    const sql = "SELECT id,email,approved,payment_ok FROM users WHERE email = ? AND password = ?";
    con.query(sql, [req.body.email, req.body.password], (err, result) => {
        if (err) return res.json({Status: "Error", Error: err});

        if (result.length > 0) {
            req.session.userId = result[0].id; 
            req.session.email = result[0].email;
            return res.json({
                Status: "Success",
                Email: req.session.email,
                PaymentOk: result[0].payment_ok,
                id: result[0].id,
                approved: result[0].approved
            });
        } else {
            return res.json({Status: "Error", Error: "Invalid Email/Password"});
        }
    });
});

app.get('/get-referrer', (req, res) => {
    const { referrerId } = req.query;  // Extract referrerId from query string

    console.log('Received referrerId:', referrerId);  // Log the referrerId for debugging

    try {
        if (!referrerId) {
            return res.json({ status: 'error', error: 'No referrerId provided' });
        }

        // Query to get referrer details by referrerId
        const getReferrerSql = "SELECT name FROM users WHERE id = ?";
        con.query(getReferrerSql, [referrerId], (err, result) => {
            if (err) {
                return res.json({ status: 'error', error: 'Failed to retrieve referrer' });
            }

            if (result.length > 0) {
                // Return referrer name to the frontend
                return res.json({
                    status: 'success',
                    refer_by: result[0].name 
                });
            } else {
                return res.json({ status: 'error', error: 'Referrer not found' });
            }
        });
    } catch (error) {
        console.error('Error:', error);
        return res.json({ status: 'error', error: 'An unexpected error occurred' });
    }
});
app.post('/register-country', (req, res) => {
    if (!req.session?.userId) {
      return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }
  
    const { country, name, phoneNumber } = req.body;
  
    if (!country || !name || !phoneNumber) {
      return res.json({ status: 'error', error: 'All fields (name, phoneNumber, country) are required' });
    }
  
    const updateSql = 'UPDATE users SET country = ?, name = ?, phoneNumber = ? WHERE id = ?';
    con.query(updateSql, [country, name, phoneNumber, req.session.userId], (err, result) => {
      if (err) {
        return res.json({ status: 'error', error: 'Failed to update details' });
      }
  
      if (result.affectedRows > 0) {
        return res.json({ status: 'success', message: 'Details updated successfully' });
      } else {
        return res.json({ status: 'error', error: 'Failed to update details' });
      }
    });
  });
  
  
  
 
  app.post('/register', (req, res) => {
    const { name, email, phoneNumber, password, refer_by } = req.body;

    const checkEmailSql = 'SELECT * FROM users WHERE email = ?';
    con.query(checkEmailSql, [email], (err, existingUsers) => {
      if (err) {
        return res.json({ status: 'error', error: 'Database error' });
      }
  
      if (existingUsers.length > 0) {
        return res.json({ status: 'error', error: 'Email already registered' });
      }
  
      // Insert user into database
      const user = { name, email, phoneNumber, password, refer_by };
      const sql = 'INSERT INTO users SET ?';
      con.query(sql, user, (err, result) => {
        if (err) {
            console.log(err);
            
          return res.json({ status: 'error', error: 'Failed to register user' });
        }
  
        // Save session with userId
        req.session.userId = result.insertId;
        req.session.save((saveErr) => {
          if (saveErr) {
            console.error('Session save error:', saveErr);
            return res.json({ status: 'error', error: 'Failed to save session' });
          }
  
          return res.json({ status: 'success', userId: result.insertId });
        });
      });
    });
  });
  




app.get('/check-session', (req, res) => {
    if (req.session.userId) {
        return res.json({
            status: 'success',
            message: 'Session exists',
            userId: req.session.userId
        });
    } else {
        return res.json({
            status: 'error',
            message: 'No active session'
        });
    }
});


const getUserIdFromSession = (req, res, next) => {
    if (req.session && req.session.userId) {
      res.json({ userId: req.session.userId });
    } else {
      res.status(401).json({ error: 'User not authenticated' });
    }
  };
  
  app.get('/getUserIdFromSession', getUserIdFromSession);





app.get('/getUserData', (req, res) => {
    if(!req.session.userId) {
        return res.json({Status: 'Error', Error: 'User not logged in'});
    }

    const sql = "SELECT * FROM users WHERE id = ?";
    con.query(sql, [req.session.userId], (err, result) => {
        if (err) {
            return res.json({Status: 'Error', Error: 'Failed to fetch user data'});
        }

        if (result.length > 0) {
            return res.json({Status: 'Success', Data: result[0]});
        } else {
            return res.json({Status: 'Error', Error: 'User not found'});
        }
    });
});

app.get('/getAllAdmins', (req, res) => {
    const sql = "SELECT * FROM admins";
    con.query(sql, (err, result) => {
        if (err) {
            return res.json({Status: 'Error', Error: 'Failed to fetch admins data'});
        }

        if (result.length > 0) {
            return res.json({Status: 'Success', Data: result});
        } else {
            return res.json({Status: 'Error', Error: 'No admins found'});
        }
    });
});

app.get('/approved-users',verifyToken, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10;
    const searchTerm = req.query.searchTerm || ''; 
    const sortKey = req.query.sortKey || 'id';
    const sortDirection = req.query.sortDirection || 'asc'; 


    let sql = `SELECT id,balance,team,name,email,phoneNumber,backend_wallet,trx_id,total_withdrawal,CurrTeam,refer_by,password,level_updated,level FROM  users
    WHERE 
        approved = 1
        AND payment_ok = 1`;

    if (searchTerm) {
        sql += ` AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')`;
    } else {
        sql += ` AND (CurrTeam >= 3 OR team >= 5) `;
    }


    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE approved = 1 AND payment_ok = 1 ${searchTerm ? `AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')` : ''}`;


    con.query(countSql, (countErr, countResult) => {
        if (countErr) {
            console.error('Count Query Error:', countErr); 
            return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
        }

        const totalCount = countResult[0].totalCount;

        sql += ` ORDER BY ${sortKey} ${sortDirection}`;

        con.query(sql, (err, result) => {
            if (err) {
                console.error('Main Query Error:', err); 
                return res.status(500).json({ success: false, message: 'An error occurred while fetching approved users.' });
            }

            res.status(200).json({
                success: true,
                approvedUsers: result,
                
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });


        
});


function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 


    if (!token) {
        return res.status(403).json({ success: false, message: `No token provided ${token}` });
    }

    jwt.verify(token, 'your_secret_key', (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, message: 'Failed to authenticate token.' });
        }

        if (!decoded.isAdmin) {
            return res.status(403).json({ success: false, message: 'Not authorized to access this resource.' });
        }

        next();
    });
}



app.get('/users-by-email', verifyToken,(req, res) => {



    const email = req.query.email || ''; 
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10;
    const sortKey = req.query.sortKey || 'id';
    const sortDirection = req.query.sortDirection || 'asc';

    let sql = `SELECT id,balance,team,backend_wallet, name,email,phoneNumber,trx_id,total_withdrawal,CurrTeam,refer_by,password,level_updated,level FROM  users
    WHERE 
        approved = 1
        AND payment_ok = 1`;
    if (email) {
        sql += ` AND (email LIKE '%${email}%' OR id = '${email}' OR trx_id LIKE '%${email}%')`;
    } else {
        sql += ` AND (CurrTeam >= 3 OR team >= 5)`;
    }


    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE approved = 1 AND payment_ok = 1 ${email ? `AND email LIKE '%${email}%'` : ''}`;


    con.query(countSql, (countErr, countResult) => {
        if (countErr) {
            console.error('Count Query Error:', countErr); 
            return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
        }

        const totalCount = countResult[0].totalCount;

        sql += ` ORDER BY ${sortKey} ${sortDirection}`;

        con.query(sql, (err, result) => {
            if (err) {
                console.error('Main Query Error:', err);
                return res.status(500).json({ success: false, message: 'An error occurred while fetching users by email.' });
            }

            res.status(200).json({
                success: true,
                users: result,
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });
});

app.post('/collectBonus', (req, res) => {
    const userId = req.session.userId;
    if (!userId) {
        console.log('Unauthorized access attempt');
        return res.status(401).json({ status: 'error', message: 'Unauthorized' });
    }

    const getUserQuery = `SELECT level_updated, balance, level FROM users WHERE id = ?`;
    con.query(getUserQuery, [userId], (err, result) => {
        if (err) {
            console.error('Database error while retrieving user data:', err);
            return res.status(500).json({ status: 'error', message: 'Failed to retrieve user data' });
        }

        if (result.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        const user = result[0];

        if (user.level_updated === 1) {
            const getBonusAmountQuery = `SELECT increment_amount FROM level_bonus WHERE level = ?`;

            con.query(getBonusAmountQuery, [user.level], (err, bonusResult) => {
                if (err) {
                    console.error('Database error while retrieving bonus amount:', err);
                    return res.status(500).json({ status: 'error', message: 'Failed to retrieve bonus amount' });
                }

                if (bonusResult.length === 0) {
                    return res.status(404).json({ status: 'error', message: 'No bonus amount found for this level' });
                }

                const bonusAmount = bonusResult[0].increment_amount;

                const updateBalanceQuery = `UPDATE users SET balance = balance + ?, level_updated = 0 WHERE id = ?`;
                con.query(updateBalanceQuery, [bonusAmount, userId], (err) => {
                    if (err) {
                        console.error('Database error while updating balance:', err);
                        return res.status(500).json({ status: 'error', message: 'Failed to update balance' });
                    }

                    const logBonusQuery = `INSERT INTO bonus_history_level_up (user_id, bonus_amount) VALUES (?, ?)`;
                    con.query(logBonusQuery, [userId, bonusAmount], (err) => {
                        if (err) {
                            console.error('Database error while logging bonus collection:', err);
                            return res.status(500).json({ status: 'error', message: 'Failed to log bonus collection' });
                        }

                        res.json({ status: 'success', message: 'Bonus collected and logged successfully!' });
                    });
                });
            });
        } else if (user.level_updated === 0) {
            console.log('Bonus already collected for user ID:', userId);
            return res.status(403).json({ status: 'error', message: 'You have already collected your bonus' });
        } else {
            console.log('User is not eligible to collect the bonus for user ID:', userId);
            return res.status(403).json({ status: 'error', message: 'You are not eligible to collect the bonus' });
        }
    });
});

app.get('/getBonusDetails', (req, res) => {
    const query = `
        SELECT 
            l.level, 
            lb.increment_amount AS bonus, 
            l.min_team, 
            l.max_team
        FROM 
            levels AS l
        LEFT JOIN 
            level_bonus AS lb 
        ON 
            l.level = lb.level
        ORDER BY 
            l.level
    `;

    con.query(query, (err, results) => {
        if (err) {
            console.error('Database error while retrieving level data:', err);
            return res.status(500).json({ status: 'error', message: 'Failed to retrieve level data' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No level data found' });
        }

        // Map results to a more readable format
        const levelsData = results.map(row => ({
            level: row.level,
            bonus: row.bonus,
            minTeam: row.min_team,
            maxTeam: row.max_team
        }));

        res.json({ status: 'success', levels: levelsData });
    });
});


app.post('/changePassword', (req, res) => {
    const { username, oldPassword, newPassword } = req.body;
  
    const sql = "SELECT password FROM admins WHERE username = ?";
    
    con.query(sql, [username], (err, result) => {
      if (err || result.length === 0) {
        return res.json({ message: 'Username not found' });
      }
  
      const storedPassword = result[0].password;
  
      if (storedPassword !== oldPassword) { 
        return res.json({ message: 'Old password is incorrect' });
      }
  
      const updateSql = "UPDATE admins SET password = ? WHERE username = ?";
      
      con.query(updateSql, [newPassword, username], (updateErr, updateResult) => {
        if (updateErr) {
          return res.json({ message: 'Failed to update password' });
        }
  
        return res.json({ message: 'Password updated successfully' });
      });
    });
  });
  
  app.get('/user-stats/:userId', (req, res) => {
    const userId = req.params.userId;

    // Query to fetch user's level and team size
    const userQuery = `
        SELECT level, team 
        FROM users 
        WHERE id = ?`;

    // Query to fetch level requirements
    const levelQuery = `
        SELECT id AS level, min_team 
        FROM levels`;

    // Query to calculate the average backend_wallet of referred users
    const avgWalletQuery = `
        SELECT AVG(backend_wallet) AS average_wallet 
        FROM users 
        WHERE refer_by = ?`;

    con.query(userQuery, [userId], (err, userResult) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch user data' });
        }

        if (userResult.length === 0) {
            return res.status(404).json({ status: 'error', error: 'User not found' });
        }

        const { level, team } = userResult[0];

        con.query(levelQuery, (err, levelResult) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to fetch level data' });
            }

            const currentLevel = levelResult.find(l => l.level == level);
            if (!currentLevel) {
                return res.status(400).json({ status: 'error', error: 'Invalid user level' });
            }

            const minTeam = currentLevel.min_team;
            const completionPercentage = ((team / minTeam) * 100).toFixed(2);

            con.query(avgWalletQuery, [userId], (err, avgResult) => {
                if (err) {
                    return res.status(500).json({ status: 'error', error: 'Failed to calculate average backend_wallet' });
                }

                const averageWallet = avgResult[0]?.average_wallet || 0;

                res.json({
                    status: 'success',
                    userId,
                    currentLevel: level,
                    teamSize: team,
                    minTeamRequirement: minTeam,
                    completionPercentage: parseFloat(completionPercentage),
                    averageWallet: parseFloat(averageWallet).toFixed(2)
                });
            });
        });
    });
});


app.get('/products', (req, res) => {
    const getProductsSql = 'SELECT * FROM products'; 

    con.query(getProductsSql, (err, products) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch products' });
        }

        res.json({ status: 'success', products });
    });
});
app.post('/updateBalance', (req, res) => {
    const { productId, reward } = req.body;

    if (!req.session.userId) { 
        return res.json({ Status: 'Error', Error: 'User not logged in' });
    }

    const checkLastClickedSql = 'SELECT last_clicked FROM user_product_clicks WHERE user_id = ? AND product_id = ?';
    con.query(checkLastClickedSql, [req.session.userId, productId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to check the last clicked time' });
        }

        const currentTime = new Date();

        if (result.length > 0) {
            const lastClicked = new Date(result[0].last_clicked);
            const timeDifference = currentTime - lastClicked;

            if (timeDifference < 12 * 60 * 60 * 1000) { 
                return res.json({ status: 'error', error: 'You have completed your task' });
            }
        }

        const updateBalanceSql = `UPDATE users SET balance = balance + ?, backend_wallet = backend_wallet - ? WHERE id = ?`;
        con.query(updateBalanceSql, [reward, reward, req.session.userId], (err, updateResult) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to update the balance and backend wallet' });
            }

            const updateLastClickedSql = `
                INSERT INTO user_product_clicks (user_id, product_id, last_clicked) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE last_clicked = VALUES(last_clicked)
            `;

            con.query(updateLastClickedSql, [req.session.userId, productId, currentTime], (err, clickResult) => {
                if (err) {
                    return res.status(500).json({ status: 'error', error: 'Failed to update the last clicked time' });
                }

                return res.json({ status: 'success', message: 'Balance and backend wallet updated successfully' });
            });
        });
    });
});













app.get('/getUserTaskStatus/:userId', (req, res) => {
    const userId = req.params.userId;
    const sql = 'SELECT * FROM user_product_clicks WHERE user_id = ?';
    
    con.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch user task status' });
        }
        
        const taskStatus = results.reduce((acc, curr) => {
            acc[curr.product_id] = curr.last_clicked;
            return acc;
        }, {});

        res.json({ status: 'success', taskStatus });
    });
});
app.put('/updateProfile', upload.single('profilePicture'), async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }
  
    const { name, city, currentPassword, newPassword } = req.body;
  
    if (!name || !city) {
      return res.status(400).json({ status: 'error', error: 'Name and city are required' });
    }
  
    const newProfilePicturePath = req.file ? req.file.path : null;
  
    con.query('SELECT profile_picture, password FROM users WHERE id = ?', [req.session.userId], async (err, result) => {
      if (err) {
        return res.status(500).json({ status: 'error', error: 'Failed to fetch user data' });
      }
  
      const existingProfilePicture = result[0]?.profile_picture;
      const userPassword = result[0]?.password;
  
      // Validate current and new passwords
      if (currentPassword && newPassword) {
        if (userPassword !== currentPassword) {
          return res.status(400).json({ status: 'error', error: 'Current password is incorrect' });
        }
  
        const updatePasswordQuery = 'UPDATE users SET password = ? WHERE id = ?';
        con.query(updatePasswordQuery, [newPassword, req.session.userId], (err) => {
          if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to update password' });
          }
        });
      }
  
      // Update user data
      const profilePictureToSave = newProfilePicturePath || existingProfilePicture;
      const updateUserDataQuery = 'UPDATE users SET name = ?, city = ?, profile_picture = ? WHERE id = ?';
      con.query(updateUserDataQuery, [name, city, profilePictureToSave, req.session.userId], (err) => {
        if (err) {
          return res.status(500).json({ status: 'error', error: 'Failed to update profile' });
        }
  
        res.json({ status: 'success', message: 'Profile updated successfully' });
  
        // Delete old profile picture if a new one was uploaded
        if (existingProfilePicture && newProfilePicturePath) {
          fs.unlink(existingProfilePicture, (err) => {
            if (err) {
              console.error('Failed to delete existing profile picture:', err);
            }
          });
        }
      });
    });
  });
  
  


app.post('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                return res.json({ Status: 'Error', Error: 'Failed to logout' });
            }

            return res.json({ Status: 'Success', Message: 'Logged out successfully' });
        });
    } else {
        return res.json({ Status: 'Error', Error: 'No session to logout' });
    }
});

app.get('/referrals', async (req, res) => {
    const referrerId = req.query.referrerId;

    if (!referrerId) {
        return res.status(400).json({status: 'error', error: 'Referrer ID is required'});
    }

    const sqlReferrals = `
        SELECT * FROM referrals 
        WHERE referrer_id = ? 
    `;

    con.query(sqlReferrals, [referrerId], async (err, referrals) => {
        if (err) {
            return res.status(500).json({status: 'error', error: 'Failed to fetch referrals'});
        }

        if (referrals.length > 0) {
            const referredIds = referrals.map(referral => referral.referred_id);
            const sqlUsers = `
                SELECT COUNT(*) as approvedCount FROM users 
                WHERE id IN (?) 
                AND approved = 1;
            `;

            con.query(sqlUsers, [referredIds], (err, results) => {
                if (err) {
                    return res.status(500).json({status: 'error', error: 'Failed to fetch users'});
                }

                return res.json({status: 'success', approvedReferralsCount: results[0].approvedCount});
            });
        } else {
            return res.status(404).json({status: 'error', error: 'No approved referrals found for this referrer ID'});
        }
    });
});

    
    


app.post('/admin-login', (req, res) => {
    const sentloginUserName = req.body.LoginUserName;
    const sentLoginPassword = req.body.LoginPassword;

    const sql = 'SELECT * FROM admins WHERE username = ? && password = ?';
    const values = [sentloginUserName, sentLoginPassword];

    con.query(sql, values, (err, results) => {
        if (err) {
            res.status(500).send({ error: err });
        }
        if (results.length > 0) {
            const token = jwt.sign({ username: sentloginUserName, isAdmin: true }, 'your_secret_key', { expiresIn: '30d' });
            res.status(200).send({ token });
        } else {
            res.status(401).send({ message: `Credentials don't match!` });
        }
    });
});


app.get('/todayApproved', (req, res) => {
    const sql = `
        SELECT 
            u.*, 
            r.name AS referrer_name, 
            r.email AS referrer_email 
        FROM users u
        LEFT JOIN users r ON u.refer_by = r.id
        WHERE u.approved = 1 AND DATE(u.approved_at) = CURDATE()
    `;

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});


app.put('/updateUserDataEasyPaisa/:id', (req, res) => {
    const { id } = req.params;
    const { refer_by, trx_id,  sender_name, sender_number, email } = req.body;
    
    console.log('User ID:', id);
    console.log('Received data:', { refer_by, trx_id,  sender_name, sender_number, email });

    if (!refer_by || !trx_id  || !sender_name || !sender_number) {
        return res.status(400).json({ status: 'error', message: 'All fields are required' });
    }

    const updateQuery = `
        UPDATE users 
        SET 
            refer_by = ?, 
            trx_id = ?, 
            sender_name = ?, 
            sender_number = ?, 
            email = ?
        WHERE id = ?
    `;
    const queryParams = [refer_by, trx_id,  sender_name, sender_number, email, id];

    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating user data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update user data' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        res.json({ status: 'success', message: 'User data updated successfully' });
    });
});


app.put('/rejectUser/:userId', (req, res) => {
    const userId = req.params.userId;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const sql = `
        UPDATE users 
        SET 
            rejected = 1, 
            payment_ok = 0,
            approved = 0,
       
                        rejected_at = CURRENT_TIMESTAMP 
        WHERE id = ? AND rejected = 0`;

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to reject user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found or already rejected' });
        }

        res.json({ status: 'success', message: 'User rejected successfully' });
    });
});

app.get('/rejectedUsers', (req, res) => {
    const sql = 'SELECT * FROM users WHERE rejected = 1 ';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {

        }
    });
});

app.get('/EasypaisaUsers', (req, res) => {
    const { type } = req.query;
    console.log(type);

    const sql = `
        SELECT 
            u.id, 
            u.trx_id, 
            u.refer_by, 
            u.name, 
            u.email, 
            u.sender_name, 
            u.sender_number, 
            ref.name AS referrer_name 
        FROM 
            users u
        LEFT JOIN 
            users ref 
        ON 
            u.refer_by = ref.id
        WHERE 
            u.approved = 0 
            AND u.payment_ok = 1 
            AND u.type = ?`;

    con.query(sql, [type], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});


app.post('/withdraw', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }

    const userId = req.session.userId;
    const { amount, accountName, accountNumber, bankName, CurrTeam, totalWithdrawn, team } = req.body;

    if (!amount || !accountName || !accountNumber || !bankName) {
        return res.status(400).json({ status: 'error', error: 'All fields are required' });
    }

    const checkRequestSql = `
        SELECT * FROM withdrawal_requests
        WHERE user_id = ? AND approved = 'pending' AND reject = 0
    `;

    con.query(checkRequestSql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to check for existing requests', details: err.message });
        }

        if (results.length > 0) {
            return res.status(400).json({ status: 'error', error: 'You already have a pending withdrawal request' });
        }

        const getUserAttemptsSql = `
            SELECT withdrawalAttempts FROM users WHERE id = ?
        `;

        con.query(getUserAttemptsSql, [userId], (err, userResults) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to fetch user withdrawal attempts', details: err.message });
            }

            if (userResults.length === 0) {
                return res.status(500).json({ status: 'error', error: 'User not found' });
            }

            let userAttempts = userResults[0].withdrawalAttempts;

            const effectiveAttempts = userAttempts > 3 ? 3 : userAttempts;

            const checkLimitsSql = `
                SELECT allow_limit 
                FROM withdraw_limit 
                WHERE withdrawalAttempts = ?
            `;

            con.query(checkLimitsSql, [effectiveAttempts], (err, limitResults) => {
                if (err) {
                    return res.status(500).json({ status: 'error', error: 'Failed to check withdrawal limits', details: err.message });
                }

                if (limitResults.length === 0) {
                    return res.status(500).json({ status: 'error', error: 'Withdrawal limit not found' });
                }

                const minimumLimit = limitResults[0].allow_limit;
                console.log('Minimum withdrawal limit:', minimumLimit);

                const getExchangeFeeSql = `
                    SELECT fee FROM exchange_fee WHERE id = 1
                `;

                con.query(getExchangeFeeSql, (err, feeResults) => {
                    if (err) {
                        return res.status(500).json({ status: 'error', error: 'Failed to fetch exchange fee', details: err.message });
                    }

                    if (feeResults.length === 0) {
                        return res.status(500).json({ status: 'error', error: 'Exchange fee not found' });
                    }

                    const feePercentage = feeResults[0].fee;
                    const fee = (amount * feePercentage) / 100;
                    const amountAfterFee = amount - fee;

                    console.log('Amount after fee:', amountAfterFee);

                    if (amountAfterFee < minimumLimit) {
                        return res.status(400).json({ status: 'error', error: `Minimum withdrawal amount is ${minimumLimit}$` });
                    }
                    con.beginTransaction(err => {
                        if (err) {
                            return res.status(500).json({ status: 'error', error: 'Failed to start transaction' });
                        }

                        const withdrawSql = `
                            INSERT INTO withdrawal_requests (user_id, amount, account_name, account_number, bank_name, CurrTeam, total_withdrawn, team, request_date, approved, fee)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), 'pending', ?)
                        `;

                        con.query(withdrawSql, [userId, amountAfterFee, accountName, accountNumber, bankName, CurrTeam, totalWithdrawn, team, fee], (err, withdrawResult) => {
                            if (err) {
                                return con.rollback(() => {
                                    res.status(500).json({ status: 'error', error: 'Failed to make withdrawal', details: err.message });
                                });
                            }

                            con.commit(err => {
                                if (err) {
                                    return con.rollback(() => {
                                        res.status(500).json({ status: 'error', error: 'Failed to commit transaction', details: err.message });
                                    });
                                }
                                res.json({ status: 'success', message: 'Withdrawal request submitted successfully' });
                            });
                        });
                    });
                });
            });
        });
    });
});





app.get('/fetchLevelsData', (req, res) => {
    const sql = 'SELECT * FROM levels';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});

app.put('/updateLevelData', (req, res) => {
    const { id, min_team, max_team, level } = req.body;

    if (!min_team || !max_team || !level) {
        return res.status(400).json({ status: 'error', message: 'Min Team, Max Team, and Level are required' });
    }

    let updateQuery = `
        UPDATE levels
        SET 
            min_team = ?,
            max_team = ?,
            level = ?
        WHERE id = ?`;
    let queryParams = [min_team, max_team, level, id];


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating level data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update level data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Level data not found' });
        }

        res.json({ status: 'success', message: 'Level data updated successfully' });
    });
});

app.get('/fetchLimitsData', (req, res) => {
    const sql = 'SELECT * FROM withdraw_limit';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});

app.put('/updateWithdrawData', (req, res) => {
    const { id, withdrawalAttempts	, allow_limit } = req.body;

    if (!withdrawalAttempts || !allow_limit ) {
        return res.status(400).json({ status: 'error', message: 'Min Team, Max Team, and Level are required' });
    }

    let updateQuery = `
        UPDATE withdraw_limit

        SET 
            withdrawalAttempts = ?,
            allow_limit = ?
        WHERE id = ?`;
    let queryParams = [withdrawalAttempts, allow_limit,  id];


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating level data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update level data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Level data not found' });
        }

        res.json({ status: 'success', message: 'Level data updated successfully' });
    });
});

app.get('/fetchCommissionData', (req, res) => {
    const sql = 'SELECT * FROM commission';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});

app.put('/updateCommissionData', (req, res) => {
    const { id, direct_bonus, indirect_bonus } = req.body;

    if (!direct_bonus || !indirect_bonus) {
        return res.status(400).json({ status: 'error', message: 'Direct Bonus and Indirect Bonus are required' });
    }

    let updateQuery;
    let queryParams;

    if (id === 0) {
        updateQuery = `
            UPDATE commission
            SET 
                direct_bonus = ?,
                indirect_bonus = ?
            WHERE id = 0`;
        queryParams = [direct_bonus, indirect_bonus];
    } else {
        updateQuery = `
            UPDATE commission
            SET 
                direct_bonus = ?,
                indirect_bonus = ?
            WHERE id = ?`;
        queryParams = [direct_bonus, indirect_bonus, id];
    }


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating commission data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update commission data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Commission data not found' });
        }

        res.json({ status: 'success', message: 'Commission data updated successfully' });
    });
});


app.put('/updateUser', (req, res) => {
    if (!req.body.id) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const { id, name, email, balance,CurrTeam, trx_id, total_withdrawal,level, level_updated,backend_wallet,password } = req.body;

    const sql = `
        UPDATE users 
        SET     
            name = ?, 
            email = ?, 
            balance = ?, 
            CurrTeam = ?,
            trx_id = ?, 
            total_withdrawal = ? ,
            level=?,
            password = ?,
            level_updated =?,
            backend_wallet=?
        WHERE id = ?`;

    con.query(sql, [name, email, balance,CurrTeam, trx_id, total_withdrawal,level,password, level_updated,backend_wallet, id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to update user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        res.json({ status: 'success', message: 'User updated successfully' });
    });
});



const queryAsync = (query, params) => {
    return new Promise((resolve, reject) => {
        con.query(query, params, (error, results) => {
            if (error) {
                return reject(error);
            }
            resolve(results);
        });
    });
};

const insertNotificationQuery = `
    INSERT INTO notifications (user_id, msg, created_at)
    VALUES (?, ?, NOW())`;

const updateBalancesAndWallet = async (userId, depth = 0) => {
    if (depth >= 7) return; // Limit updates to 7 levels of referrers

    try {
        const referrerResult = await queryAsync(`
            SELECT refer_by
            FROM users
            WHERE id = ?
        `, [userId]);

        const referrerId = referrerResult[0]?.refer_by;

        if (referrerId) {
            const commissionResult = await queryAsync(`
                SELECT direct_bonus, indirect_bonus, extra_balance
                FROM commission
                WHERE id = ?
            `, [depth]);

            const { direct_bonus, indirect_bonus, extra_balance } = commissionResult[0] || {};
            const feeResult = await queryAsync(`
                SELECT joining_fee
                FROM joining_fee
                WHERE id = 1
            `);

            const joiningFee = feeResult[0]?.joining_fee || 0;
            const directBonusAmount = (direct_bonus * joiningFee) / 100 || 0;
            const indirectBonusAmount = (indirect_bonus * joiningFee) / 100 || 0;
            const extraBalanceAmount = (extra_balance * joiningFee) / 100 || 0;

            await queryAsync(`
                UPDATE users
                SET 
                    balance = balance + ?,
                    backend_wallet = backend_wallet + ?,
                    extra_balance = extra_balance + ?
                WHERE id = ?
            `, [directBonusAmount, indirectBonusAmount, extraBalanceAmount, referrerId]);

            // Add notification for referrer
           

            await updateBalancesAndWallet(referrerId, depth + 1);
        }
    } catch (error) {
        console.error('Error updating balances and wallet:', error.message);
        throw error;
    }
};

app.put('/approveUser/:userId', async (req, res) => {
    const userId = req.params.userId;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    try {
        await queryAsync('START TRANSACTION');

        await queryAsync(`
            UPDATE users 
            SET 
                approved = 1, 
                payment_ok = 1,
                rejected = 0,
                approved_at = CURRENT_TIMESTAMP,
                backend_wallet = backend_wallet + (
                    SELECT joining_fee * (SELECT initial_percent FROM initial_fee WHERE id = 1) / 100
                    FROM joining_fee
                    WHERE id = 1
                )
            WHERE id = ?
        `, [userId]);

        await updateBalancesAndWallet(userId);

        const referrerResult = await queryAsync(`
            SELECT refer_by
            FROM users
            WHERE id = ?
        `, [userId]);

        const referrerId = referrerResult[0]?.refer_by;

        if (referrerId) {
            // Step 1: Calculate the new team count dynamically
            const approvedCountResult = await queryAsync(`
                SELECT COUNT(*) AS approved_count
                FROM users
                WHERE refer_by = ? AND approved = 1
            `, [referrerId]);

            const approvedCount = approvedCountResult[0]?.approved_count || 0;

            // Update the referrer's team, including the currently approving user
            await queryAsync(`
                UPDATE users
                SET team = ?
                WHERE id = ?
            `, [approvedCount, referrerId]);

            // Add notification for the referrer
            const notificationMessage = 'Successfully! A user is added to your downline';
            await queryAsync(insertNotificationQuery, [referrerId, notificationMessage]);

            // Step 2: Update the referrer's level
            await queryAsync(`

UPDATE users AS u1
JOIN levels AS l ON u1.team >= l.min_team AND u1.team <= l.max_team
SET 
    u1.level = l.level,
    u1.level_updated = 1
WHERE u1.id = ? AND u1.level <> l.level


            `, [referrerId]);
            


        }

        await queryAsync('COMMIT');
        res.status(200).json({ status: 'success', message: 'User approved and referrer chain updated' });
    } catch (error) {
        console.error('Transaction error:', error.message);
        await queryAsync('ROLLBACK');
        res.status(500).json({ status: 'error', error: 'Transaction failed' });
    }
});




app.get('/notifications', (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }

    const sql = 'SELECT id , msg, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC'; // Adjust your SQL query accordingly

    con.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch notifications' });
        }

        const formattedResults = results.map(notification => ({
            id: notification.id,
            message: notification.msg,
            createdAt: notification.created_at
        }));

        res.json(formattedResults);
    });
});

app.post('/update-password', (req, res) => {
    const userId = req.session.userId;
    const { currentPassword, newPassword } = req.body;

    if (!userId) {
        return res.status(401).json({ success: false, message: 'User not logged in' });
    }

    const getPasswordSql = 'SELECT password FROM users WHERE id = ?';

    con.query(getPasswordSql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const currentStoredPassword = results[0].password;

        if (currentPassword !== currentStoredPassword) {
            return res.status(400).json({ success: false, message: 'Current password is incorrect' });
        }

        const updatePasswordSql = 'UPDATE users SET password = ? WHERE id = ?';
        
        con.query(updatePasswordSql, [newPassword, userId], (err) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Failed to update password' });
            }

            res.json({ success: true, message: 'Password updated successfully' });
        });
    });
});

app.get('/withdrawal-requests', (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).json({ error: 'User not logged in' });
    }

    const sql = 'SELECT user_id, request_date, reject,account_number,account_name, amount, bank_name, approved FROM withdrawal_requests WHERE user_id = ? ORDER BY request_date DESC';

    con.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch withdrawal requests' });
        }

        const formattedResults = results.map(request => ({
            id: request.user_id,
            date: request.request_date,
            amount: request.amount,
            bank_name: request.bank_name,
            approved: request.approved,
            reject: request.reject,
            account_number:request.account_number,
            account_name:request.account_name

        }));
        res.json(formattedResults);
    });
});


app.post('/reject-withdrawal', async (req, res) => {
    const { requestId, userId } = req.body; 

    if (!requestId || !userId) {
        return res.status(400).json({ error: 'Request ID and User ID are required' });
    }

    const updateWithdrawalRequestsSql = `
        UPDATE withdrawal_requests 
        SET reject=1, approved='rejected', reject_at=CURRENT_TIMESTAMP 
        WHERE id=? AND user_id=? ;
    `;

   
    const insertNotificationSql = `
        INSERT INTO notifications (user_id, msg, created_at)
        VALUES (?, 'Your withdrawal has been rejected', CURRENT_TIMESTAMP)`;


    try {
        con.query(updateWithdrawalRequestsSql, [requestId, userId], (err, result) => {
            if (err) {
                console.error('Error executing query', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (result.affectedRows > 0) {
                con.query(insertNotificationSql, [userId], (notifErr) => {
                    if (notifErr) {
                        console.error('Error inserting notification', notifErr);
                        return res.status(500).json({ error: 'Failed to insert notification' });
                    }

                    return res.json({ message: 'Withdrawal request rejected and notification sent!' });
                });
            } else {
                return res.status(404).json({ error: 'No matching withdrawal request found' });
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/approve-withdrawal', async (req, res) => {
    const { userId, requestId, amount } = req.body;

    if (!userId || !requestId || !amount) {
        return res.status(400).json({ error: 'User ID, request ID, and amount are required' });
    }

    const updateWithdrawalRequestsSql = `
        UPDATE withdrawal_requests 
        SET approved = 'approved', reject = 0, approved_time = CURRENT_TIMESTAMP 
        WHERE id = ? AND user_id = ? AND approved = 'pending'`;

    const updateUserBalanceAndTotalWithdrawalSql = `
        UPDATE users
        SET balance = balance - ?,
            total_withdrawal = total_withdrawal + ?,
            withdrawalAttempts = withdrawalAttempts + 1
        WHERE id = ?`;

    const deleteUserClicksSql = `
        DELETE FROM user_product_clicks
        WHERE user_id = ?`;

    const deleteReferralsSql = `
        DELETE FROM referrals
        WHERE referrer_id = ?`;

    const insertNotificationSql = `
        INSERT INTO notifications (user_id, msg, created_at)
        VALUES (?, 'withdraw  has been completed', CURRENT_TIMESTAMP)`;

    con.beginTransaction(error => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        con.query(updateWithdrawalRequestsSql, [requestId, userId], (error, results) => {
            if (error) {
                console.log(error);
                
                return con.rollback(() => {
                    res.status(500).json({ error: 'Internal Server Error' });
                });
            }

            if (results.affectedRows === 0) {
                return res.status(400).json({ error: 'Could not find the withdrawal request or it is already approved' });
            }

            con.query(updateUserBalanceAndTotalWithdrawalSql, [amount, amount, userId], (error, results) => {
                if (error) {
                    console.log(error);
                    
                    return con.rollback(() => {
                        res.status(500).json({ error: 'Internal Server Error' });
                    });
                }

                con.query(deleteUserClicksSql, [userId], (error, results) => {
                    if (error) {
                        console.log(error);
                        
                        return con.rollback(() => {
                            res.status(500).json({ error: 'Internal Server Error' });
                        });
                    }

                    con.query(deleteReferralsSql, [userId], (error, deleteResult) => {
                        if (error) {
                            return con.rollback(() => {
                                res.status(500).json({ error: 'Failed to delete referrals' });
                            });
                        }

                        con.query(insertNotificationSql, [userId], (error, notificationResult) => {
                            if (error) {
                                console.log(error);
                                return con.rollback(() => {
                                    res.status(500).json({ error: 'Failed to insert notification' });
                                });
                            }

                            con.commit(error => {
                                if (error) {
                                    return con.rollback(() => {
                                        res.status(500).json({ error: 'Failed to commit transaction' });
                                    });
                                }

                                res.json({ message: 'Withdrawal request approved, balance and total withdrawal updated, user clicks data, referrals deleted, and notification sent successfully!' });
                            });
                        }); 
                    });
                });
            });
        });
    });
});
app.get('/notifications/unseen-count', (req, res) => {
    const userId=req.session.userId;

    const unseenCountSql = `SELECT COUNT(*) AS unseenCount FROM notifications WHERE user_id = ? AND seen = 0`;

    con.query(unseenCountSql, [userId], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Failed to retrieve unseen notifications count' });
        }
        res.json({ unseenCount: results[0].unseenCount });
    });
});

app.get('/messages/unseen-count', (req, res) => {
    const userId=req.session.userId;
console.log(userId);

    const unseenCountSql = `SELECT COUNT(*) AS unseenCount FROM messages WHERE user_id = ? AND seen = 0`;

    con.query(unseenCountSql, [userId], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Failed to retrieve unseen notifications count' });
        }
        res.json({ unseenCount: results[0].unseenCount });
    });
});

app.post('/mark-notifications-seen', async (req, res) => {
const {userId} = req.body;
console.log(userId);

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required' });
    }

    const updateSeenStatusSql = `
        UPDATE notifications
        SET seen = 1
        WHERE user_id = ? `

    try {
        const [result] = await con.promise().query(updateSeenStatusSql, [userId]);

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Notifications marked as seen' });
        } else {
            res.status(400).json({ message: 'No unseen notifications found' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/mark-messages-seen', async (req, res) => {
    const {userId} = req.body;
    console.log(userId);
    
        if (!userId) {
            return res.status(400).json({ error: 'User ID is required' });
        }
    
        const updateSeenStatusSql = `
            UPDATE messages
            SET seen = 1
            WHERE user_id = ? `
    
        try {
            const [result] = await con.promise().query(updateSeenStatusSql, [userId]);
    
            if (result.affectedRows > 0) {
                console.log(result.affectedRows);
                
                res.status(200).json({ message: 'Notifications marked as seen' });
            } else {
                res.status(400).json({ message: 'No unseen notifications found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    });
    
    


app.put('/updateHolderNumber', (req, res) => {
    const { holder_number, userId } = req.body;

    if (!holder_number || !userId) {
        return res.status(400).json({ success: false, message: 'Holder number and user ID are required.' });
    }

    const sql = 'UPDATE users_accounts SET coin_address = ? WHERE user_id = ?';
    const values = [holder_number, userId];

    con.query(sql, values, (err, result) => {
        if (err) {
            console.error('Failed to update holder number:', err);
            return res.status(500).json({ success: false, message: 'Failed to update holder number.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        res.json({ success: true, message: 'Holder number updated successfully.' });
    });
});

app.put('/updateUserAccount/:userId', (req, res) => {
    const user_id = req.params.userId;
    const { accountNumber, nameOnAccount, bankName } = req.body;

    if (!user_id || !accountNumber || !nameOnAccount || !bankName) {
        return res.status(400).json({ status: 'error', message: 'User ID, Account Number, Name on Account, and Bank Name are required' });
    }

    let updateQuery = `
        UPDATE users_accounts
        SET 
            holder_name = ?,
            holder_number = ?,
            bankName = ?
        WHERE user_id = ?`;
    let updateParams = [nameOnAccount, accountNumber, bankName, user_id];

    con.query(updateQuery, updateParams, (err, updateResult) => {
        if (err) {
            console.error('Error updating user account:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update user account' });
        }

        if (updateResult.affectedRows === 0) {
            let insertQuery = `
                INSERT INTO users_accounts (user_id, holder_name, holder_number, bankName)
                VALUES (?, ?, ?, ?)`;
            let insertParams = [user_id, nameOnAccount, accountNumber, bankName];

            con.query(insertQuery, insertParams, (err, insertResult) => {
                if (err) {
                    console.error('Error inserting user account:', err);
                    return res.status(500).json({ status: 'error', error: 'Failed to insert user account' });
                }

                res.json({ status: 'success', message: 'User account inserted successfully' });
            });
        } else {
            res.json({ status: 'success', message: 'User account updated successfully' });
        }
    });
});

  
app.get('/getUserAccount/:userId', (req, res) => {
    const user_id = req.params.userId;
      if (!user_id) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }
     let fetchQuery = 'SELECT * FROM users_accounts WHERE user_id = ?';
     let queryParams = [user_id];
     con.query(fetchQuery, queryParams, (err, result) => {
         if (err) {
             console.error('Error fetching user account:', err);
             return res.status(500).json({ status: 'error', error: 'Failed to fetch user account' });
         }
         if (result.length === 0) {
             return res.status(404).json({ status: 'error', message: 'User account not found' });
         }
         res.json({ status: 'success', userAccount: result[0] });
         console.log(result[0]);
         
     })
});


app.get('/fetchClickedProducts', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ status: 'error', error: 'User not authenticated' });
    }

    const userId = req.session.userId;
    const today = new Date().toISOString().split('T')[0]; 

    const getClickedProductsSql = `
             SELECT p.*, upc.last_clicked
        FROM products p
        LEFT JOIN user_product_clicks upc 
        ON p.id = upc.product_id AND upc.user_id = ?
    `;

    con.query(getClickedProductsSql, [userId], (err, productResults) => {
        if (err) {
            console.error('Fetch clicked products query error:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch clicked products' });
        }

        const products = productResults.map(product => ({
            ...product,
            canClick: !product.last_clicked || new Date(product.last_clicked).toISOString().split('T')[0] !== today
        }));

        const productCount = products.length;

        if (productCount > 0) {
            const updateWalletSql = `
              UPDATE users
SET 
    today_wallet = CASE
        WHEN COALESCE(last_wallet_update, '') <> ? THEN (backend_wallet * 0.1 / ?)
        ELSE today_wallet
    END,
    backend_wallet = CASE
        WHEN COALESCE(last_wallet_update, '') <> ? THEN backend_wallet - backend_wallet * 0.1
        ELSE backend_wallet
    END,
    last_wallet_update = CASE
        WHEN COALESCE(last_wallet_update, '') <> ? THEN ?
        ELSE last_wallet_update
    END
WHERE id = ? AND (COALESCE(last_wallet_update, '') <> ?)
            `;

            con.query(updateWalletSql, [today, productCount, today, today, today, userId, today], (err) => {
                if (err) {
                    console.error('Update wallet query error:', err);
                    return res.status(500).json({ status: 'error', error: 'Failed to update wallet' });
                }

                const getUserDataSql = 'SELECT today_wallet FROM users WHERE id = ?';
                con.query(getUserDataSql, [userId], (err, userResults) => {
                    if (err) {
                        console.error('Fetch user wallet query error:', err);
                        return res.status(500).json({ status: 'error', error: 'Failed to fetch user data' });
                    }

                    const today_wallet = userResults[0]?.today_wallet || 0;
                    res.json({ 
                        status: 'success', 
                        products,
                        today_wallet 
                    });
                });
            });
        } else {
            res.json({ 
                status: 'success', 
                products: [],
                today_wallet: 0 
            });
        }
    });
});


app.get('/all-withdrawal-requests', (req, res) => {
    const sql = `
        SELECT wr.id, wr.user_id, wr.amount, wr.account_name, wr.bank_name, wr.CurrTeam, 
               wr.account_number, wr.approved, wr.team, wr.total_withdrawn, u.name AS user_name ,u.balance
        FROM withdrawal_requests wr
        JOIN users u ON wr.user_id = u.id
        WHERE wr.approved = "pending" AND wr.reject = "0"
    `;

    con.query(sql, (error, results) => {
        if (error) {
            res.status(500).json({ error: 'Internal Server Error' });
            return;
        }
        const mappedResults = results.map(item => ({
            id: item.id,
            user_id: item.user_id,
            amount: item.amount,
            account_name: item.account_name,
            bank_name: item.bank_name,
            CurrTeam: item.CurrTeam,
            account_number: item.account_number,
            approved: item.approved === 1,
            team: item.team,
            total_withdrawn: item.total_withdrawn,
            balance: item.balance,
            user_name: item.user_name // Add user_name here
        }));
        res.json(mappedResults);
    });
});

app.get('/withdrawalRequestsApproved', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "approved" && reject = 0';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved withdrawal requests' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No approved withdrawal requests found' });
        }

        res.json({ status: 'success', data: results });
    });
});
app.get('/withdrawalRequestsRejected', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "rejected" ';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved withdrawal requests' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No approved withdrawal requests found' });
        }

        res.json({ status: 'success', data: results });
    });
});

app.put('/products/:id', (req, res) => {
    const id = req.params.id;
    const { description, link,  imgLink } = req.body;
console.log(req.body);
    if (!description || !link  || !imgLink) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const sql = 'UPDATE products SET description = ?, link = ?,  imgLink = ? WHERE id = ?';

    con.query(sql, [description, link, imgLink, id], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while updating the product.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Product not found.' });
        }

        res.status(200).json({ success: true, message: 'Product updated successfully.' });
    });
});

app.delete('/products/:id', (req, res) => {
    const id = req.params.id;

    if (!id) {
        return res.status(400).json({ success: false, message: 'ID is required.' });
    }

    const sql = 'DELETE FROM products WHERE id = ?';
    con.query(sql, [id], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while deleting the product.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Product not found.' });
        }

        res.status(200).json({ success: true, message: 'Product deleted successfully.' });
    });
});


app.get('/products', (req, res) => {
    const sql = 'SELECT * FROM products';
    
    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the products.' }); 
        }

        res.status(200).json({ success: true, data: results });
    });
});

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    let sql = `SELECT * FROM users WHERE id = ${con.escape(userId)}`;
    con.query(sql, (err, result) => {
        if (err) {
            res.status(500).send(err);
            return;
        }

        if (result.length === 0) {
            res.status(404).send({ message: 'User not found' });
            return;
        }

        res.send(result[0]);
    });
});




app.get('/get-accounts', (req, res) => {
    const sql = 'SELECT * FROM accounts'; 

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching accounts.' });
        }

        res.status(200).json({ success: true, accounts: results });
    });
});
app.get('/receive-accounts', (req, res) => {
    const status = 'on';
    const sql = 'SELECT * FROM accounts WHERE status = ? LIMIT 1'; 

    con.query(sql, [status], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching accounts.' });
        }

        if (result.length > 0) {
            res.status(200).json({ success: true, account: result[0] });
        } else {
            res.status(404).json({ success: false, message: 'No account found with the given status.' });
        }
    });
});


app.get('/get-fee', (req, res) => {
    const feeSql = 'SELECT joining_fee FROM joining_fee WHERE id = ?';
    const accountId = 1;

    con.query(feeSql, [accountId], (feeErr, feeResult) => {
        if (feeErr) {
            console.error('Error fetching fee:', feeErr);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (feeResult.length > 0) {
            const feeValue = feeResult[0].joining_fee;

            const rateSql = 'SELECT rate FROM usd_rate LIMIT 1';
            con.query(rateSql, (rateErr, rateResult) => {
                if (rateErr) {
                    console.error('Error fetching rate:', rateErr);
                    return res.status(500).json({ success: false, message: 'An error occurred while fetching the rate.' });
                }

                if (rateResult.length > 0) {
                    const rate = rateResult[0].rate;
                    const feeInPkr = feeValue * rate;

                    res.status(200).json({ success: true, fee: feeValue, feeInPkr: feeInPkr.toFixed(0) });
                } else {
                    res.status(404).json({ success: false, message: 'No rate found in the usd_rate table.' });
                }
            });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});

app.get('/get-percentage', (req, res) => {
    const sql = 'SELECT initial_percent FROM initial_fee WHERE id = 1'; 
    con.query(sql, (err, result) => {
         if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }
         else{
            if (result.length > 0) {
                const feeValue = result[0].initial_percent;
                res.status(200).json({ success: true, initial_percent: feeValue });
            } else {
                res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
            }
         }
    })

  
});

app.get('/get-rate', (req, res) => {
    const sql = 'SELECT rate FROM usd_rate WHERE id = ?';

    const accountId = 1;

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (result.length > 0) {
            const rateValue = result[0].rate;
            res.status(200).json({ success: true, rate: rateValue });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.get('/get-offer', (req, res) => {
    const sql = 'SELECT offer FROM offer WHERE id = ?'; 

    const accountId = 1;

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching offer:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the offer.' });
        }

        if (result.length > 0) {
            const offerValue = result[0].offer; 
            res.status(200).json({ success: true, offer: offerValue });
        } else {
            res.status(404).json({ success: false, message: 'No offer found for the given account ID.' });
        }
    });
});


app.post('/update-fee', (req, res) => {
    const { newFeeValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE joining_fee SET joining_fee = ? WHERE id = ?';

    con.query(updateSql, [newFeeValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});


app.post('/update-percentage', (req, res) => {
    const { newFeeValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE initial_fee   SET initial_percent = ? WHERE id = 1';

    con.query(updateSql, [newFeeValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.get('/pending-users', (req, res) => {
    const searchTerm = req.query.searchTerm;

    if (!searchTerm) {
        return res.status(400).json({ success: false, message: 'No search term provided.' });
    }

    let sql = 'SELECT * FROM users WHERE payment_ok = 0 AND approved = 0 AND (name LIKE ? OR email LIKE ?)';
    const searchTermWildcard = `%${searchTerm}%`;
    const params = [searchTermWildcard, searchTermWildcard];

    con.query(sql, params, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the pending users.' });
        }

        res.status(200).json({
            success: true,
            pendingUsers: result
        });
    });
});






app.post('/payment', (req, res) => {
    const { trx_id, sender_name, sender_number, id } = req.body;
    const payment_ok = 1;
    const rejected = 0;

    // Check if the trx_id already exists in the users table
    const checkQuery = 'SELECT COUNT(*) AS count FROM users WHERE trx_id = ?';
    con.query(checkQuery, [trx_id], (checkErr, checkResults) => {
        if (checkErr) {
            return res.status(500).json({ status: 'error', error: 'Database error' });
        }

        // Inside the '/payment' route
        if (checkResults[0].count > 0) {
            // The trx_id already exists; return an error response
            return res.status(400).json({ status: 'error', error: 'Transaction ID already in use' });
        }


        // The trx_id doesn't exist; update the user's payment data
        const sql = 'UPDATE users SET trx_id = ?, sender_name = ?, sender_number = ?, payment_ok = ?, rejected = ? WHERE id = ?';

        con.query(sql, [trx_id, sender_name, sender_number, payment_ok, rejected, id], (err, result) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to update payment data' });
            }

            res.json({ status: 'success' });
        });
    });
});





app.post('/update-usd', (req, res) => {
    const { newFeeValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE usd_rate SET rate = ? WHERE id = ?';

    con.query(updateSql, [newFeeValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.post('/update-offer', (req, res) => {
    const { newOfferValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE offer SET offer = ? WHERE id = ?';

    con.query(updateSql, [newOfferValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});


app.delete('/delete-user/:id', (req, res) => {
    const userId = req.params.id;
    const sql = 'DELETE FROM users WHERE id = ?';

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while deleting the user.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'User deleted successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'User not found.' });
        }
    });
});
app.delete('/delete-7-days-old-users', (req, res) => {
    const sql = `
        DELETE FROM users 
        WHERE payment_ok=0 AND approved=0 AND created_at <= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
    `;

    con.query(sql, (err, result) => {
        if(err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "An error occurred while deleting the users." });
        }

        res.status(200).json({ success: true, message: `${result.affectedRows} users deleted successfully.` });
    });
});
// Route for uploading an image
app.post('/upload', upload.single('image'), (req, res) => {
    const { filename, path: filePath } = req.file;
    const uploadTime = new Date();
  
    const query = 'INSERT INTO images (file_name, file_path, upload_time) VALUES (?, ?, ?)';
    const values = [filename, filePath, uploadTime];
  
    con.query(query, values, (error, results) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'Database error' });
      }
  
      res.json({ message: 'File uploaded successfully' });
    });
  });
  
  // Route for fetching all images
  app.get('/getImages', (req, res) => {
    const query = 'SELECT * FROM images ORDER BY upload_time DESC';
  
    con.query(query, (error, results) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'An error occurred while fetching images' });
      }
  
      res.json(results); // Send the list of images
    });
  });
  app.delete('/deleteImage/:id', (req, res) => {
    const { id } = req.params;
  
    // Fetch the image record from the database
    const query = 'SELECT * FROM images WHERE id = ?';
    con.query(query, [id], (error, results) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'Database error' });
      }
  
      if (results.length > 0) {
        const imagePath = results[0].file_path;
  
        // Check if the file exists before deleting
        fs.exists(imagePath, (exists) => {
          if (!exists) {
            return res.status(404).json({ message: 'Image file not found' });
          }
  
          // Delete the image file from the server
          fs.unlink(imagePath, (err) => {
            if (err) {
              console.error(err);
              return res.status(500).json({ error: 'Error deleting image file' });
            }
  
            // Delete the image record from the database
            const deleteQuery = 'DELETE FROM images WHERE id = ?';
            con.query(deleteQuery, [id], (err) => {
              if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Error deleting image record' });
              }
  
              res.json({ message: 'Image deleted successfully' });
            });
          });
        });
      } else {
        res.status(404).json({ message: 'Image not found' });
      }
    });
  });
app.post('/update-accounts', (req, res) => {
    const accounts = req.body.accounts;

    if (!accounts || !Array.isArray(accounts)) {
        return res.status(400).json({ success: false, message: 'Invalid account data.' });
    }

    accounts.forEach(account => {
        if (account.account_id) {  
            const sql = 'UPDATE accounts SET account_name = ?, account_number = ?, status = ? WHERE account_id = ?';
            const values = [account.account_name, account.account_number, account.status, account.account_id];

            con.query(sql, values, (err) => {
                if (err) {
                    console.error('Failed to update account:', err);
                }
            });
        } else {
            console.error('Account ID is NULL, skipping update.');
        }
    });

    res.json({ success: true, message: 'Accounts updated successfully.' });
});

app.get('/dashboard-data', (req, res) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const tomorrow = new Date(today);
    tomorrow.setDate(today.getDate() + 1);

    const firstDayOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
    const lastDayOfMonth = new Date(today.getFullYear(), today.getMonth() + 1, 0);

    const sql = `
        SELECT 
            (SELECT COUNT(*) FROM users WHERE approved = 1 AND id NOT BETWEEN 1 AND 10) as approvedUsersCount,
            (SELECT COUNT(*) FROM users WHERE approved = 1 AND approved_at >= ? AND approved_at < ? AND id NOT BETWEEN 1 AND 10) as approvedUsersCountToday,
            (SELECT SUM(amount) FROM withdrawal_requests WHERE approved='approved') as totalWithdrawal,
            (SELECT SUM(amount) FROM withdrawal_requests WHERE approved = 'approved' AND approved_time >= ? AND approved_time < ?) as totalAmountToday,
            (SELECT COUNT(*) FROM users WHERE payment_ok = 0 AND approved = 0 AND id NOT BETWEEN 1 AND 10) as unapprovedUnpaidUsersCount,
            (SELECT SUM(jf.joining_fee) FROM joining_fee jf JOIN users u ON u.approved = 1 AND u.id NOT BETWEEN 1 AND 10) as totalReceived,
            (SELECT SUM(jf.joining_fee) FROM joining_fee jf JOIN users u ON u.approved = 1 AND approved_at >= ? AND approved_at < ? AND u.id NOT BETWEEN 1 AND 10) as totalReceivedToday,
            (SELECT SUM(amount) FROM withdrawal_requests WHERE approved = 'approved' AND approved_time >= ? AND approved_time <= ?) as totalAmountThisMonth,
            (SELECT SUM(jf.joining_fee) FROM joining_fee jf JOIN users u ON u.approved = 1 AND approved_at >= ? AND approved_at <= ? AND u.id NOT BETWEEN 1 AND 10) as totalReceivedThisMonth
    `;

    con.query(sql, [today, tomorrow, today, tomorrow, today, tomorrow, firstDayOfMonth, lastDayOfMonth, firstDayOfMonth, lastDayOfMonth], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching dashboard data.' });
        }

        const dashboardData = {
            approvedUsersCount: results[0].approvedUsersCount,
            approvedUsersCountToday: results[0].approvedUsersCountToday,
            totalWithdrawal: results[0].totalWithdrawal,
            totalAmountToday: results[0].totalAmountToday,
            unapprovedUnpaidUsersCount: results[0].unapprovedUnpaidUsersCount,
            totalReceived: results[0].totalReceived,
            totalReceivedToday: results[0].totalReceivedToday,
            totalAmountThisMonth: results[0].totalAmountThisMonth,
            totalReceivedThisMonth: results[0].totalReceivedThisMonth
        };

        res.status(200).json({ success: true, dashboardData });
    });
});

app.get('/bonus-settings', (req, res) => {
    const fetchSettingsQuery = 'SELECT * FROM bonus_settings';
    
    con.query(fetchSettingsQuery, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch bonus settings' });
        }
        
        res.json({ status: 'success', data: result });
    });
});
app.put('/bonus-settings/:id', (req, res) => {
    const settingId = req.params.id;
    const { need_refferer, reward } = req.body;
    
    const updateSettingQuery = `
        UPDATE bonus_settings
        SET need_refferer = ?, reward = ?
        WHERE id = ?
    `;

    con.query(updateSettingQuery, [need_refferer, reward, settingId], (err, result) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ status: 'error', error: 'Failed to update bonus setting' });
        }

        res.json({ status: 'success', message: 'Bonus setting updated successfully' });
    });
});

app.get('/get-total-withdrawal', (req, res) => {
    const sql = 'SELECT SUM(amount) AS totalWithdrawal FROM withdrawal_requests';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the total withdrawal.' });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: 'No withdrawal requests found.' });
        }

        res.status(200).json({ success: true, totalWithdrawal: result[0].totalWithdrawal });
    });
});
app.delete('/delete-old-rejected-users', (req, res) => {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const deleteOldRejectedUsersSql = `
        DELETE FROM users
        WHERE rejected = 1 AND rejected_at < ?`;

    con.query(deleteOldRejectedUsersSql, [sevenDaysAgo], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json({ message: 'Old rejected user records deleted successfully' });
    });
});
app.delete('/delete-rejected-users', (req, res) => {
    const deleteRejectedUsersSql = `
        DELETE FROM users
        WHERE rejected = 1`;

    con.query(deleteRejectedUsersSql, (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.affectedRows === 0) {
            return res.json({ message: 'No rejected users to delete' });
        }

        res.json({ message: 'Rejected users deleted successfully' });
    });
});


app.get('/unapproved-unpaid-users-count', (req, res) => {
    const sql = 'SELECT COUNT(*) AS count FROM users WHERE payment_ok = 0 AND approved = 0';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the users count.' });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: 'No users found.' });
        }

        res.status(200).json({ success: true, count: result[0].count });
    });
});

app.post('/sendMessage', async (req, res) => {
  const { userId, messageContent } = req.body;

  if (!userId || !messageContent) {
    return res.status(400).json({ status: 'error', error: 'User ID and message content are required' });
  }

  const insertMessageQuery = 'INSERT INTO messages (user_id, message_content) VALUES (?, ?)';
  con.query(insertMessageQuery, [userId, messageContent], (err, result) => {
    if (err) {
      return res.status(500).json({ status: 'error', error: 'Failed to send message' });
    }

    res.json({ status: 'success', message: 'Message sent successfully' });
  });
});

app.get('/allMessages', async (req, res) => {
    const fetchAllMessagesQuery = 'SELECT * FROM messages';
    con.query(fetchAllMessagesQuery, (err, result) => {
      if (err) {
        return res.status(500).json({ status: 'error', error: 'Failed to fetch messages' });
      }
  
      res.json({ status: 'success', messages: result });
    });
  });
  app.get('/messages/:userId', (req, res) => {
    const userId = req.params.userId;
  
    const fetchMessagesQuery = 'SELECT * FROM messages WHERE user_id = ? ORDER BY sent_time DESC';
    con.query(fetchMessagesQuery, [userId], (err, result) => {
      if (err) {
        console.error('Error fetching messages:', err);
        return res.status(500).json({ status: 'error', error: 'Failed to fetch messages' });
      }
  
      res.json({ status: 'success', messages: result });
    });
  });
  const fetchApprovedUserNames = (referByUserId) => {
    return new Promise((resolve, reject) => {
      const fetchNamesQuery = 'SELECT id, name , profile_picture FROM users WHERE refer_by = ? AND approved = 1';
      con.query(fetchNamesQuery, [referByUserId], (err, results) => {
        if (err) {
          reject(err);
        } else {
          resolve(results); // Resolve with the results containing both id and name
        }
      });
    });
  };
  
  
  app.get('/approvedUserNames/:referByUserId', async (req, res) => {
    const { referByUserId } = req.params;
  
    try {
      const users = await fetchApprovedUserNames(referByUserId);
      res.json({ status: 'success', users });
    } catch (error) {
      console.error('Error fetching approved users:', error);
      res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
    }
  });

  app.post('/payment-crypto', (req, res) => {
    const { trx_id} = req.body;
    const id = req.session.userId;
    const payment_ok = 1;
    const rejected = 0;
    const type=1;

    const checkQuery = 'SELECT COUNT(*) AS count FROM users WHERE trx_id = ?';
    con.query(checkQuery, [trx_id], (checkErr, checkResults) => {
        if (checkErr) {
            return res.status(500).json({ status: 'error', error: 'Database error' });
        }

if (checkResults[0].count > 0) {
    return res.status(400).json({ status: 'error', error: 'Transaction ID already in use' });
  }
  

        const sql = 'UPDATE users SET trx_id = ?,  type = ?, payment_ok = ?, rejected = ? WHERE id = ?';

        con.query(sql, [trx_id, type, payment_ok, rejected, id], (err, result) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to update payment data' });
            }

            res.json({ status: 'success' });
        });
    });
});
app.post('/delete-withdrawal', async (req, res) => {
    const { requestId, userId } = req.body;

    if (!requestId || !userId) {
        return res.status(400).json({ error: 'Request ID and User ID are required' });
    }   

    const updateWithdrawalRequestsSql = `
        DELETE FROM withdrawal_requests 
        WHERE id=? AND user_id=? ;
    `;

    try {
        con.query(updateWithdrawalRequestsSql, [requestId, userId], (err, result) => {
            if (err) {
                console.error('Error executing query', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (result.affectedRows > 0) {
                return res.json({ message: 'Withdrawal request deleted successfully' });
            } else {
                return res.status(404).json({ error: 'No matching withdrawal request found' });
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }

});
https.createServer(options, app).listen(PORT, () => {
  console.log('HTTPS Server running on port '+PORT);
});

