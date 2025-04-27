# Changelog

## 0.8.2

* ADD: Add function `with_endpoint` to `Builder` that allows to change the
metric endpoint from the default `/metrics`. (thanks @jward-bw)

## 0.8.1

* CHANGE: Update dependency prometheus to version 0.12.
* SECURITY FIX: Update dependency tiny_http to version 0.8. Version 0.7 was vulnerable see #18 for more information [thanks @lapawa].

## 0.8

* CHANGE: Update prometheus dependency from 0.10 to 0.11.

## 0.7

* CHANGE: Complete rewrite of the crate to allow for a nicer interface. For how to migrate from earlier versions see the MIGRATION.md document.

## 0.6

* FIX: Infinity loop when using debug with StartError
* CHANGE: Reexport prometheus crate to make usage simpler.

## 0.5

* CHANGE: Updated prometheus dependency

## 0.4

* ADD: Feature flag for `log` crate.
