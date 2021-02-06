<?php

session_start();

if (!$_SESSION["login"]) {
    header("Location: login.php");
    return;
}

$command = $_POST["command"];
$submit = $_POST["submit"];
$logout = $_POST["logout"];

if (isset($logout)) {
    unset($_SESSION["login"]);
    session_destroy();

    header("Location: login.php");
    return;
}

if (isset($submit)) {
    exec($command);
}

?>

<!DOCTYPE html>
<html>
    <head>
        <title>Smag Development | Login</title>
        <link type="text/css" rel="stylesheet" href="materialize.min.css" media="screen,projection" />
    </head>

    <body class="container">
        <div class="row">
                <div class="col s12 14 offset-14">
                        <div class="card">
                                <div class="card-action">
                                        <h1 class="center-align">Enter a command</h1>
                                </div>
                                <div class="card-content">
                                        <form action="admin.php" method="POST">
                                                <div class="form-field">
                                                        <label for="command">Command</label>
                                                        <input type="text" name="command" placeholder="Command..." />
                                                </div>
                                                <br>
                                                <div class="form-field center-align">
                                                        <button name="submit" class="btn-large black">Send</button>
                                                        <button name="logout" class="btn-large red">Logout</button>
                                                </div>
                                        </form>
                                </div>
                        </div>
                </div>
        </div>
    </body>
</html>

