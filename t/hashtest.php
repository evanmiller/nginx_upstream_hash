<?php

$base_url = "http://localhost:8081/";
$failures = 0;
$passes = 0;

function assert_equal($one, $two, $name)
{
    global $failures, $passes;
    if ($one == $two) {
        $passes++;
    } else {
        echo "Test failed: $name\n";
        echo "   Expected:  $one\n";
        echo "   Got:       $two\n";
        echo "\n";
        $failures++;
    }
}

$memcache = new Memcache;

for ($i=0; $i<20; $i++) {
	$memcache->connect("localhost", 11211 + $i);

}

$test_vals = array(
    'quux' => 'baz',
    'foo' => 'bar',
    'shazam' => 'kerpow!',
    'verbum' => 'word',
    'felix' => 'happy',
    'ren' => 'stimpy',
    'Frank' => 'Julie',
    'peanuts' => 'cracker jacks',
    'all-gaul' => 'is divided into three parts',
    'the-more-tests-the-better' => 'i says',
    'adsfasw' => 'QA#(@()!@*$$*!!',
    'Swing-Low' => 'Sweet Cadillac',
    'can-has-exclamations!' => 'but no spaces or percents',
    "Smile_if_you_like_UTF-8_\xa6\x3a" => "\xa6\x3b",
    "8103*$)&^#@*^@!&!)*!_(#" => "whew"
);

$curl = curl_init();
curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

foreach ($test_vals as $k => $v ) {
	assert_equal(TRUE, $memcache->set("/$k", $v), "Setting key \"$k\" via PECL");

    $memcache_url = rawurlencode($k);
    curl_setopt($curl, CURLOPT_URL, "$base_url$memcache_url");
	assert_equal($v, curl_exec($curl), "Fetching key \"$k\" via Nginx");
}

$test_vals = array(
	't1'	=> 200,
	't2'	=> 200,
	't3'	=> 200,
	't4'	=> 500,
	't5'	=> 200,
	't6'	=> 200,
	't7'	=> 200,
);

foreach ($test_vals as $location => $status) {
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($curl, CURLOPT_URL, "$base_url/$location/");
	curl_exec($curl);

	assert_equal($status, curl_getinfo($curl, CURLINFO_HTTP_CODE),
												"HTTP status for $location");
}

curl_close($curl);

if ($failures > 0) {
    echo "$passes tests paseed, $failures tests failed\n";
} else {
    echo "All $passes tests passed\n";
}
