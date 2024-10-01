const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");

// MySQL 연결 설정
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "koad9401", // MySQL root 비밀번호
  database: "myapp",
});

// MySQL 연결 오류 처리
db.connect((err) => {
  if (err) {
    console.error("MySQL 연결 오류:", err);
    process.exit(1);
  } else {
    console.log("MySQL 연결 성공");
  }
});

// 파일 업로드 설정
const fs = require("fs");

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = "uploads/";
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir); // 파일 저장 경로
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // 파일명 설정
  },
});

// upload 변수를 storage 설정 후 선언
const upload = multer({ storage });

// Express 앱 초기화
const app = express();
app.use(express.json());
app.use(cors());

// 정적 파일 제공 경로 설정
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// 로그인 및 토큰 발급
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  // 먼저 users 테이블에서 사용자를 찾습니다.
  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, results) => {
      if (err) {
        console.error("Query error:", err);
        return res.status(500).json({ error: "Database query failed" });
      }

      if (results.length === 0) {
        // users 테이블에 사용자가 없으면 companies 테이블에서 찾습니다.
        console.log("No user found in users table, checking companies table");
        db.query(
          "SELECT * FROM companies WHERE username = ?",
          [username],
          async (err, results) => {
            if (err || results.length === 0) {
              console.error("User not found or query error:", err);
              return res.status(401).json({ error: "Invalid credentials" });
            }

            const user = results[0];
            const isPasswordValid = await bcrypt.compare(
              password,
              user.password
            );

            if (isPasswordValid) {
              const isAdmin = user.is_admin || false;
              const isActive = user.is_active;

              if (isAdmin || isActive) {
                const token = jwt.sign(
                  { id: user.id, is_admin: isAdmin },
                  "secret_key",
                  { expiresIn: "1h" }
                );

                return res.json({
                  token,
                  id: user.id,
                  is_admin: isAdmin,
                  is_active: isActive,
                  companyName: user.company_name,
                });
              } else {
                return res.status(403).json({
                  error: "Account is not activated",
                  token: jwt.sign({ id: user.id }, "secret_key", {
                    expiresIn: "1h",
                  }),
                  id: user.id,
                });
              }
            } else {
              return res.status(401).json({ error: "Invalid credentials" });
            }
          }
        );
      } else {
        // users 테이블에서 사용자를 찾은 경우
        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (isPasswordValid) {
          const isAdmin = user.is_admin;
          const isActive = user.is_active;

          if (isAdmin || isActive) {
            const token = jwt.sign(
              { id: user.id, is_admin: isAdmin },
              "secret_key",
              { expiresIn: "1h" }
            );

            return res.json({
              token,
              id: user.id,
              is_admin: isAdmin,
              is_active: isActive,
              companyName: user.company_name,
            });
          } else {
            return res.status(403).json({
              error: "Account is not activated",
              token: jwt.sign({ id: user.id }, "secret_key", {
                expiresIn: "1h",
              }),
              id: user.id,
            });
          }
        } else {
          return res.status(401).json({ error: "Invalid credentials" });
        }
      }
    }
  );
});

// 인증된 관리자만 접근 가능
app.get("/api/admin", (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token missing" });
  }

  jwt.verify(token, "secret_key", (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Token invalid" });
    }

    if (!decoded.is_admin) {
      return res.status(403).json({ error: "Admin access only" });
    }

    res.json({ message: "Welcome Admin!" });
  });
});

// 박람회 리스트 조회
app.get("/api/expos", (req, res) => {
  db.query("SELECT * FROM expos", (err, results) => {
    if (err) {
      console.error("Database query failed:", err);
      return res.status(500).json({ error: "Database query failed" });
    }
    res.json(results);
  });
});

// 박람회 추가
app.post("/api/expos", (req, res) => {
  const { name, period, note } = req.body;
  const query = "INSERT INTO expos (name, period, note) VALUES (?, ?, ?)";

  db.query(query, [name, period, note], (err, result) => {
    if (err) {
      console.error("Database insert failed:", err);
      return res.status(500).json({ error: "Database insert failed" });
    }
    res.json({ id: result.insertId, name, period, note });
  });
});

// 박람회 수정
app.put("/api/expos/:id", (req, res) => {
  const { id } = req.params;
  const { name, period, note } = req.body;
  const query = "UPDATE expos SET name = ?, period = ?, note = ? WHERE id = ?";

  db.query(query, [name, period, note, id], (err, result) => {
    if (err) {
      console.error("Database update failed:", err);
      return res.status(500).json({ error: "Database update failed" });
    }
    res.json({ message: "Expo updated successfully" });
  });
});

// 박람회 삭제
app.delete("/api/expos/:id", (req, res) => {
  const { id } = req.params;
  const query = "DELETE FROM expos WHERE id = ?";

  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Database delete failed:", err);
      return res.status(500).json({ error: "Database delete failed" });
    }
    res.json({ message: "Expo deleted successfully" });
  });
});

// 박람회 이름 조회
app.get("/api/expos/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM expos WHERE id = ?", [id], (err, results) => {
    if (err || results.length === 0) {
      console.error("Expo not found or query error:", err, results);
      return res.status(404).json({ error: "Expo not found" });
    }
    res.json(results[0]);
  });
});

// 업체 추가 API
app.post("/api/companies", async (req, res) => {
  const {
    expo_id,
    company_name,
    username,
    password,
    product_type,
    ceo_name,
    manager_name,
    phone_number,
    is_active,
    note,
  } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const companyQuery = `
    INSERT INTO companies (expo_id, company_name, username, password, product_type, ceo_name, manager_name, phone_number, is_active, note)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    companyQuery,
    [
      expo_id,
      company_name,
      username,
      hashedPassword,
      product_type,
      ceo_name,
      manager_name,
      phone_number,
      is_active,
      note,
    ],
    (err, result) => {
      if (err) {
        console.error("Database insert failed (companies):", err);
        return res.status(500).json({ error: "Database insert failed" });
      }

      const userQuery = `
        INSERT INTO users (username, password, is_admin, is_verified, is_signed, is_active, company_name)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;

      db.query(
        userQuery,
        [username, hashedPassword, 0, 0, 0, is_active, company_name], // 회사 이름 포함
        (err, userResult) => {
          if (err) {
            console.error("Database insert failed (users):", err);
            return res.status(500).json({ error: "Database insert failed" });
          }

          res.json({
            companyId: result.insertId,
            userId: userResult.insertId,
            message: "Company and user added successfully",
          });
        }
      );
    }
  );
});

// 업체 수정 API
app.put("/api/companies/:id", async (req, res) => {
  const { id } = req.params;
  const {
    expo_id,
    company_name,
    username,
    password,
    product_type,
    ceo_name,
    manager_name,
    phone_number,
    is_active,
    note,
  } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const companyQuery = `
    UPDATE companies
    SET expo_id = ?, company_name = ?, username = ?, password = ?, product_type = ?, ceo_name = ?, manager_name = ?, phone_number = ?, is_active = ?, note = ?
    WHERE id = ?
  `;

  db.query(
    companyQuery,
    [
      expo_id,
      company_name,
      username,
      hashedPassword,
      product_type,
      ceo_name,
      manager_name,
      phone_number,
      is_active,
      note,
      id,
    ],
    (err, result) => {
      if (err) {
        console.error("Database update failed (companies):", err);
        return res.status(500).json({ error: "Database update failed" });
      }

      const userQuery = `
        UPDATE users
        SET username = ?, password = ?, is_active = ?, company_name = ?
        WHERE username = ?
      `;

      db.query(
        userQuery,
        [username, hashedPassword, is_active, company_name, username], // 회사 이름 업데이트
        (err, userResult) => {
          if (err) {
            console.error("Database update failed (users):", err);
            return res.status(500).json({ error: "Database update failed" });
          }

          res.json({ message: "Company and user updated successfully" });
        }
      );
    }
  );
});

// 업체 삭제 API
app.delete("/api/companies/:id", (req, res) => {
  const { id } = req.params;

  // 먼저 companies 테이블에서 삭제할 업체의 username을 가져옴
  const getUsernameQuery = "SELECT username FROM companies WHERE id = ?";
  db.query(getUsernameQuery, [id], (err, results) => {
    if (err || results.length === 0) {
      console.error("Failed to retrieve company username:", err);
      return res
        .status(500)
        .json({ error: "Failed to retrieve company username" });
    }

    const { username } = results[0];

    const companyQuery = "DELETE FROM companies WHERE id = ?";
    db.query(companyQuery, [id], (err, result) => {
      if (err) {
        console.error("Database delete failed (companies):", err);
        return res.status(500).json({ error: "Database delete failed" });
      }

      const userQuery = "DELETE FROM users WHERE username = ?";
      db.query(userQuery, [username], (err, userResult) => {
        if (err) {
          console.error("Database delete failed (users):", err);
          return res.status(500).json({ error: "Database delete failed" });
        }

        res.json({ message: "Company and user deleted successfully" });
      });
    });
  });
});

// 업체 리스트 조회 API
app.get("/api/companies", (req, res) => {
  const { expo_id } = req.query; // 클라이언트로부터 expo_id를 쿼리 파라미터로 받음

  let query = `
    SELECT c.*, e.name as expo_name
    FROM companies c
    JOIN expos e ON c.expo_id = e.id
  `;

  if (expo_id) {
    query += ` WHERE c.expo_id = ${mysql.escape(expo_id)}`;
  }

  db.query(query, (err, results) => {
    if (err) {
      console.error("Database query failed:", err);
      return res.status(500).json({ error: "Database query failed" });
    }
    res.json(results);
  });
});

// 본인인증 API
app.post("/api/verifyIdentity", (req, res) => {
  const { userId } = req.body;

  db.query(
    "UPDATE users SET is_verified = true WHERE id = ?",
    [userId],
    (err, result) => {
      if (err) {
        console.error("Failed to update identity verification status:", err);
        return res
          .status(500)
          .json({ error: "Failed to update identity verification status" });
      }
      res.json({ message: "Identity verified successfully" });
    }
  );
});

// 본인인증 상태 체크 API
app.get("/api/verificationStatus/:userId", (req, res) => {
  const { userId } = req.params;

  // 데이터베이스에서 사용자의 인증 상태를 확인
  db.query(
    "SELECT is_verified FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      if (err) {
        console.error("Error fetching verification status:", err);
        return res
          .status(500)
          .json({ error: "Failed to fetch verification status" });
      }

      if (results.length > 0) {
        const { is_verified } = results[0];
        res.json({ status: is_verified ? 1 : 0 }); // 1이면 본인인증 완료, 0이면 미완료
      } else {
        res.status(404).json({ error: "User not found" });
      }
    }
  );
});

// 계약서 서명 업로드 API
app.post("/api/uploadSignature", upload.single("signature"), (req, res) => {
  const { userId } = req.body;
  const signaturePath = req.file.path;

  db.query(
    "UPDATE users SET signature = ?, is_signed = true WHERE id = ?",
    [signaturePath, userId],
    (err, result) => {
      if (err) {
        console.error("Failed to upload signature:", err);
        return res.status(500).json({ error: "Failed to upload signature" });
      }
      res.json({ message: "Signature uploaded successfully" });
    }
  );
});

// 계정 활성화 체크 API
app.post("/api/activateAccount", (req, res) => {
  const { userId } = req.body;

  console.log("Activate account request received for userId:", userId);

  db.query(
    "SELECT is_verified, is_signed FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      if (err || results.length === 0) {
        console.error("Failed to check activation status:", err, results);
        return res
          .status(500)
          .json({ error: "Failed to check activation status" });
      }

      console.log("User activation status fetched:", results[0]);

      const user = results[0];
      if (user.is_verified && user.is_signed) {
        console.log(
          "User is verified and signed, proceeding to activate account..."
        );

        db.query(
          "UPDATE users SET is_active = true WHERE id = ?",
          [userId],
          (err, result) => {
            if (err) {
              console.error("Failed to activate account:", err);
              return res
                .status(500)
                .json({ error: "Failed to activate account" });
            }

            console.log("Account activated successfully, Result:", result);

            // 바로 다시 데이터베이스에서 값을 읽어옴
            db.query(
              "SELECT is_active FROM users WHERE id = ?",
              [userId],
              (err, newResults) => {
                if (err) {
                  console.error("Failed to re-fetch activation status:", err);
                  return res
                    .status(500)
                    .json({ error: "Failed to re-fetch activation status" });
                }

                console.log(
                  "New is_active value fetched:",
                  newResults[0].is_active
                );

                res.json({
                  message: "Account activated successfully",
                  isActive: newResults[0].is_active,
                });
              }
            );
          }
        );
      } else {
        console.log("User is not verified or signed, cannot activate account.");
        res.status(400).json({
          error: "Identity verification or signature is not completed",
        });
      }
    }
  );
});

// 게시글 추가 API
app.post("/api/posts", upload.any(), (req, res) => {
  const { companyName, title, price, additionalInfo, memo } = req.body;
  const imagePath = req.files.length > 0 ? req.files[0].path : null;

  // 입력 값 검증
  if (!companyName || !title) {
    return res
      .status(400)
      .json({ error: "companyName 또는 title이 누락되었습니다." });
  }

  const parsedPrice = parseFloat(price);
  if (isNaN(parsedPrice)) {
    return res.status(400).json({ error: "가격이 유효한 숫자가 아닙니다." });
  }

  const query = `
    INSERT INTO posts (company_name, title, price, additional_info, image_path, memo)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [companyName, title, parsedPrice, additionalInfo, imagePath, memo],
    (err, result) => {
      if (err) {
        console.error("Failed to insert post:", err);
        return res.status(500).json({ error: "Failed to insert post" });
      }

      res.json({
        message: "Post created successfully",
        postId: result.insertId,
      });
    }
  );
});

// 게시글 조회 API
app.get("/api/posts", (req, res) => {
  const { company_name } = req.query;

  const query = `
    SELECT * FROM posts WHERE company_name = ? ORDER BY id DESC
  `; // 최신 게시글이 먼저 나오도록 id를 기준으로 역순 정렬

  db.query(query, [company_name], (err, results) => {
    if (err) {
      console.error("Failed to retrieve posts:", err);
      return res.status(500).json({ error: "Failed to retrieve posts" });
    }
    res.json(results);
  });
});

// 게시글 상세 조회 API
app.get("/api/posts/:id", (req, res) => {
  const { id } = req.params;

  const query = `
    SELECT * FROM posts WHERE id = ?
  `;

  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Failed to retrieve post:", err);
      return res.status(500).json({ error: "Failed to retrieve post" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    res.json(results[0]);
  });
});

// 게시글 수정 API
app.put("/api/posts/:id", upload.single("image"), (req, res) => {
  console.log("Received data:", req.body);
  console.log("Received file:", req.file);

  const { id } = req.params;
  const { company_name, title, price, additional_info, memo } = req.body;
  const image_path = req.file ? req.file.path : req.body.image_path; // 이미지 경로 설정

  // 가격을 정수형으로 처리하여 소수점 없이 처리
  const parsedPrice = parseFloat(price);
  if (isNaN(parsedPrice) || parsedPrice < 0) {
    return res.status(400).json({ error: "Invalid price value" });
  }

  const query = `
      UPDATE posts
      SET company_name = ?, title = ?, price = ?, additional_info = ?, image_path = ?, memo = ?
      WHERE id = ?
  `;

  db.query(
    query,
    [company_name, title, parsedPrice, additional_info, image_path, memo, id],
    (err, result) => {
      if (err) {
        console.error("Failed to update post:", err);
        return res.status(500).json({ error: "Failed to update post" });
      }
      res.json({ message: "Post updated successfully" });
    }
  );
});

// 게시글 삭제 API
app.delete("/api/posts/:id", (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM posts WHERE id = ?";

  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Failed to delete post:", err);
      return res.status(500).json({ error: "Failed to delete post" });
    }
    res.json({ message: "Post deleted successfully" });
  });
});

// 계약현황 추가 API
app.post("/api/contracts", (req, res) => {
  console.log("Received request body:", req.body);

  const {
    post_id,
    contractor_name,
    contract_date,
    item_name,
    phone_number,
    contract_amount,
    intermediate_amount,
    final_amount,
    note,
  } = req.body;

  // 빈 문자열이 들어올 경우 null로 처리
  const parsedContractAmount = contract_amount || null;
  const parsedIntermediateAmount = intermediate_amount || null;
  const parsedFinalAmount = final_amount || null;

  console.log("Parsed data:", {
    post_id,
    contractor_name,
    contract_date,
    item_name,
    phone_number,
    parsedContractAmount,
    parsedIntermediateAmount,
    parsedFinalAmount,
    note,
  });

  const query = `
    INSERT INTO contracts (post_id, contractor_name, contract_date, item_name, phone_number, contract_amount, intermediate_amount, final_amount, note)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [
      post_id,
      contractor_name,
      contract_date,
      item_name,
      phone_number,
      parsedContractAmount,
      parsedIntermediateAmount,
      parsedFinalAmount,
      note,
    ],
    (err, result) => {
      if (err) {
        console.error("Failed to insert contract:", err);
        return res.status(500).json({ error: "Failed to insert contract" });
      }
      res.json({ id: result.insertId, message: "Contract added successfully" });
    }
  );
});

// 계약현황 조회 API
app.get("/api/contracts", (req, res) => {
  const { post_id } = req.query;

  const query = `
    SELECT * FROM contracts WHERE post_id = ?
  `;

  db.query(query, [post_id], (err, results) => {
    if (err) {
      console.error("Failed to retrieve contracts:", err);
      return res.status(500).json({ error: "Failed to retrieve contracts" });
    }
    res.json(results);
  });
});

// 계약현황 상세 조회 API
app.get("/api/contracts/:id", (req, res) => {
  const { id } = req.params;

  const query = `
    SELECT * FROM contracts WHERE id = ?
  `;

  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Failed to retrieve contract:", err);
      return res.status(500).json({ error: "Failed to retrieve contract" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Contract not found" });
    }

    res.json(results[0]);
  });
});

// 계약현황 수정 API
app.put("/api/contracts/:id", (req, res) => {
  const { id } = req.params;
  const {
    contractor_name,
    contract_date,
    item_name,
    phone_number,
    contract_amount,
    intermediate_amount,
    final_amount,
    note,
  } = req.body;

  const query = `
    UPDATE contracts
    SET contractor_name = ?, contract_date = ?, item_name = ?, phone_number = ?, contract_amount = ?, intermediate_amount = ?, final_amount = ?, note = ?
    WHERE id = ?
  `;

  db.query(
    query,
    [
      contractor_name,
      contract_date,
      item_name,
      phone_number,
      contract_amount,
      intermediate_amount,
      final_amount,
      note,
      id,
    ],
    (err, result) => {
      if (err) {
        console.error("Failed to update contract:", err);
        return res.status(500).json({ error: "Failed to update contract" });
      }
      res.json({ message: "Contract updated successfully" });
    }
  );
});

// 계약현황 삭제 API
app.delete("/api/contracts/:id", (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM contracts WHERE id = ?";

  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Failed to delete contract:", err);
      return res.status(500).json({ error: "Failed to delete contract" });
    }
    res.json({ message: "Contract deleted successfully" });
  });
});

// 서버 시작
app.listen(5003, () => {
  console.log("Server is running on port 5003");
});
