<?php

foreach(glob('login_with_*.php') as $f) {
	echo '<li><a href="'.$f.'">'.$f.'</a></li> ';
}