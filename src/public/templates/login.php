<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title><? echo $title ?></title>
</head>
<body>
<?php
    foreach($scope as $t) {
        echo "<h1>$t</h1>";
    }
?>

</body>
</html>