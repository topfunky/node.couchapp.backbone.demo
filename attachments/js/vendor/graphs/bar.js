
/*jslint white: false, onevar: true, browser: true, devel: true, undef: true, nomen: true, eqeqeq: true, plusplus: true, bitwise: true, regexp: true, strict: false, newcap: true, immed: true */
/*global Raphael */

//   Usage:
//   new TopfunkyBarGraph('chart',
//                [42, 15, 21, 7],
//                { width:400,
//                  height:30,
//                  title:"Monthly Revenue",
//                  target:25,
//                  goodThreshold:20});

function TopfunkyBarGraph(elementName, datapoints, opts) {

  if ( !(this instanceof arguments.callee) ) {
    return new arguments.callee(elementName, datapoints, opts);
  }

  this.width  = opts.width;
  this.height = opts.height;

  this.barWidth          = opts.barWidth          || 4;
  this.spacing           = opts.spacing           || 1;
  this.colorBad          = opts.colorBad          || "#777";
  this.colorSatisfactory = opts.colorSatisfactory || "#aaa";
  this.colorGood         = opts.colorGood         || "#ddd";
  this.colorTarget       = opts.colorTarget       || $('body').css('background-color');
  this.good              = opts.good              || 20;
  this.satisfactory      = opts.satisfactory      || 10;
  this.bad               = opts.bad               || 5;
  this.target            = opts.target            || 15;

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
    var normalizedDatapoints = [],
      maximumDatavalue = Math.max.apply( Math, datapoints ),
      i = 0,
      barColor,
      xOffset,
      yOffset,
      bar,
      targetLine;

    for (i = 0; i < datapoints.length; i = i+1) {
      normalizedDatapoints[i] = datapoints[i] / maximumDatavalue;
    }

    // Bars
    for (i = 0; i < datapoints.length; i = i+1) {
      if (datapoints[i] >= this.good) {
        barColor = this.colorGood;
      } else if (datapoints[i] >= this.satisfactory) {
        barColor = this.colorSatisfactory;
      } else {
        barColor = this.colorBad;
      }

      xOffset = i*(this.barWidth + this.spacing) + this.width - datapoints.length*(this.barWidth + this.spacing);
      yOffset = this.height - normalizedDatapoints[i] * this.height;
      bar = this.crispRect(xOffset,
                           yOffset,
                           this.barWidth,
                           normalizedDatapoints[i] * this.height);
      bar.attr({
        stroke: barColor,
        fill: barColor
      });
    }

    // Target line
    targetLine = this.crispLine(0,
                                this.height - (this.target/maximumDatavalue)*this.height,
                                this.width,
                                0);
    targetLine.attr({stroke: this.colorTarget, fill: 'transparent'});

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

