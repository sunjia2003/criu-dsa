#!/usr/bin/env bash

set -u

adapter_prepare() {
	return 0
}

adapter_start() {
	return 0
}

adapter_ready() {
	return 0
}

adapter_before_dump() {
	return 0
}

adapter_after_restore() {
	return 0
}

adapter_stop_for_restore() {
	adapter_stop
}

adapter_verify() {
	return 0
}

adapter_stop() {
	return 0
}

adapter_collect() {
	return 0
}
