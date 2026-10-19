\set sid random(1, 2500)
\set tid random(1, 60)
\set stu random(1, 200000)
SELECT count(*) FROM test_results WHERE school_id = :sid AND master_combined_test_id = :tid AND status = 'active' AND academic_year_id IN (5554, 5132);
SELECT * FROM students WHERE email LIKE '%' || :stu || '@example.edu';
SELECT s.id, s.first_name, avg(r.score) FROM students s LEFT JOIN test_results r ON r.student_id = s.id WHERE s.school_id = :sid GROUP BY s.id, s.first_name ORDER BY s.id LIMIT 50;
SELECT id, action FROM audit_events WHERE actor_id = :stu % 5000 ORDER BY created_at DESC LIMIT 20;
SELECT * FROM test_results WHERE student_id = :stu;
