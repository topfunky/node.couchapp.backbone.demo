
/*jslint white: false, onevar: true, browser: true, devel: true, undef: true, nomen: true, eqeqeq: true, plusplus: true, bitwise: true, regexp: true, strict: false, newcap: true, immed: true */
/*global Raphael */

//   Usage:
//   new TopfunkyBulletGraph('chart',
//                1000,
//                { width:400,
//                  height:30,
//                  title:"Monthly Revenue",
//                  target:25,
//                  bad:20,
//                  satisfactory:50,
//                  good:100 });
 
function TopfunkyBulletGraph(elementName, dataValue, opts) {

  if ( !(this instanceof arguments.callee) ) {
    return new arguments.callee(elementName, dataValue, opts);
  }

  this.width  = opts.width;
  this.height = opts.height;

  this.colorBad          = opts.colorBad          || "#aaa";
  this.colorSatisfactory = opts.colorSatisfactory || "#ccc";
  this.colorGood         = opts.colorGood         || "#e6e6e6";

  this.colorDataValue    = opts.colorDataValue    || "#000000";

  this.target            = opts.target            || 15;

  this.colorCurrent = opts.colorCurrent || "#ffffff";
  this.current      = opts.current      || 0;

  ////
  // Runs Math.ceil on all arguments to make a crisp rectangle.
  // For best results, use a solid 1px stroke.

  this.crispRect = function (x, y, width, height) {
    return this.paper.rect(Math.ceil(x),
                           Math.ceil(y),
                           Math.ceil(width > 0 ? width-1 : width),
                           Math.ceil(height > 0 ? height-1 : height)
                          );
  };

  this.crispLine = function (x, y, width, height) {
    return this.paper.path("M {x} {y} l {width} {height}".supplant({
      'x': Math.ceil(x),
      'y': Math.ceil(y),
      'width': Math.ceil(width),
      'height': Math.ceil(height)
    }));
  };

  this.draw = function () {

    this.paper = Raphael(elementName, this.width, this.height);

    // Normalize
    var i = 0,
      barColor,
      xOffset,
      yOffset,
      bar;

    this.drawBadBackground();
    this.drawSatisfactoryBackground();
    this.drawGoodBackground();

    this.drawValueBar();
    this.drawTargetBar();
    this.drawCurrentValue();

  };

  this.drawBadBackground = function () {
    this.paper.rect(0, 0, this.width, this.height).attr({
      fill: this.colorBad,
      stroke: this.colorBad
    });
  };

  this.drawSatisfactoryBackground = function () {
    var xOffset = this.width * (opts.bad/opts.good);

    this.paper.rect(Math.ceil(xOffset), 0, this.width, this.height).attr({
      fill: this.colorSatisfactory,
      stroke: this.colorSatisfactory
    });
  };

  this.drawGoodBackground = function () {
    var xOffset = this.width * (opts.satisfactory/opts.good);

    this.paper.rect(Math.ceil(xOffset), 0, this.width, this.height).attr({
      fill: this.colorGood,
      stroke: this.colorGood
    });
  };

  this.drawValueBar = function () {
    // HACK Needs to work better with small heights.
    var xOffset = this.width * (dataValue/opts.good),
      dataValueY = this.height/3,
      dataValueHeight = dataValueY - (this.height > 12 ? 0 : 1);

    this.paper.rect(0, dataValueY, Math.ceil(xOffset), dataValueHeight).attr({
      fill: this.colorDataValue,
      stroke: this.colorDataValue
    });
  };

  this.drawCurrentValue = function () {
    if (this.current > 0) {
      var xOffset = this.width * (this.current/opts.good),
        currentHeight = this.height/6;

      this.paper.rect(Math.ceil(xOffset - currentHeight/2), (this.height/2 - currentHeight/2), Math.ceil(currentHeight), currentHeight).attr({
        fill: this.colorCurrent,
        stroke: this.colorCurrent
      });
    }
  };

  this.drawTargetBar = function () {
    // HACK Goes to hell at small heights. Needs to work better with floats.
    var xOffset = this.width * (this.target/opts.good),
      targetBarOffset = this.height/6,
      targetBarY = targetBarOffset - (this.height > 12 ? 2 : 0),
      targetBarHeight = targetBarOffset*4 + (this.height > 12 ? 2 : 0),
      targetBarWidth  = 2;

    this.crispRect(xOffset, targetBarY, targetBarWidth, targetBarHeight).attr({
      fill: this.colorDataValue,
      stroke: this.colorDataValue
    });
  };

  this.draw();
}


  // "{animal} on a {transport}".supplant({animal: "frog", transport: "rocket"})
  String.prototype.supplant = function (o) {
    return this.replace(/\{([^{}]*)\}/g,
                        function (a, b) {
                          var r = o[b];
                          return typeof r === 'string' || typeof r === 'number' ? r : a;
                        }
                       );
  };

