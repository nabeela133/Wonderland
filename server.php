
<?php

include("db_config.php"); // Include the database connection script
 
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    if (isset($_POST['registration'])) {

        // User registration

        $fullname = $_POST["fullname"];

        $email = $_POST["email"];

        $password = $_POST["password"];
 
        // Hash the password (you should use a secure hashing method)

        $hashed_password = password_hash($password, PASSWORD_BCRYPT);
 
        // Insert user data into the database

        $sql = "INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)";

        $stmt = $conn->prepare($sql);

        $stmt->bind_param("sss", $fullname, $email, $hashed_password);
 
        if ($stmt->execute()) {

            echo json_encode(["success" => true]);

        } else {

            echo json_encode(["success" => false]);

        }
 
        $stmt->close();

    } elseif (isset($_POST['login'])) {

        // User login

        $email = $_POST["email"];

        $password = $_POST["password"];
 
        // Retrieve user data from the database

        $sql = "SELECT id, fullname, password FROM users WHERE email = ?";

        $stmt = $conn->prepare($sql);

        $stmt->bind_param("s", $email);

        $stmt->execute();

        $stmt->store_result();

        $stmt->bind_result($id, $fullname, $db_password);
 
        if ($stmt->num_rows == 1 && $stmt->fetch() && password_verify($password, $db_password)) {

            echo json_encode(["success" => true, "fullname" => $fullname]);

        } else {

            echo json_encode(["success" => false]);

        }
 
        $stmt->close();

    }

}
 
$conn->close();

?>
