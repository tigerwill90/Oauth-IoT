<?php
  $memcd = new \Memcached('memcd');
  $list = $memcd->getServerList();
  if (empty($list)) {
				$memcd->setOption(\Memcached::OPT_LIBKETAMA_COMPATIBLE, true);
				$memcd->setOption(\Memcached::OPT_BINARY_PROTOCOL, false);
				$memcd->addServer('memcached', 11211);
	}
  if($memcd->get('msg')) {
    echo $memcd->get('msg');
  } else {
    echo "No cache : it's work !";
    $memcd->set('msg', 'Cached : it\'s work !');
  }
