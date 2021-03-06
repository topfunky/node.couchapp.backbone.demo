# CouchDB app and Backbone.js demo

A demo for the [Seattle Backbone.js meetup](http://www.meetup.com/seattle-backbone/).

This code shows how to use Node.js and CouchDB to serve JavaScript client-side applications. This application uses no authentication or security. Use Basic Auth or some other method if you plan to deploy these kinds of applications to the public.

## Installation

[Download](http://couchdb.apache.org/), install, and start the CouchDB server.

Use the CouchDB browser-based console to create a CouchDB dataabase named `time_track_demo`.

Install dependencies:

    npm install

Then:

    ./bin/push

Optionally, bundle client side assets to `attachments/js/default.js` with:

    ./bin/build

## The Code

Public client-side code is in the `attachments` directory.

CouchDB views are in the `views.js` file.

Overall configuration is in `app.js`.

## TODO

* Generate a single client-side JavaScript file from Backbone dependencies: `attachments/js/default.js`
* Generate stylesheets from SASS or Stylus.
* Compile from CoffeeScript?
* Use newer Backbone.js for the demo application
* Remove unused frameworks in `attachments`.

