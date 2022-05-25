SELECT * FROM users 
    JOIN roles ON users.role_id = roles.role_id
    --WHERE username = 'bob'
;

SELECT * FROM roles;