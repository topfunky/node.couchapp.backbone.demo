if ((typeof app) === 'undefined') {
  var app = {};
}

$.extend(true, app, {
  util: {

    toTable: function (datasets, columnTitles, callback) {
      var table = $('<table>'),
        thead, tbody, tr;

      thead = $('<thead>');
      tr = $('<tr>');

      $(columnTitles).each(function (index, columnTitle) {
        tr.append($('<th>', {
          text: columnTitle,
          'class': 'col-' + index
        }));
      });

      thead.append(tr);
      table.append(thead);


      tbody = $('<tbody>');

      $(datasets).each(function (index, data) {
        tr = $('<tr>');
        var cellContentArray = callback(index, data);
        $(cellContentArray).each(function (index, cellContentItem) {
          var td = $('<td>', {
            html: cellContentItem,
            'class': 'col-' + index
          });
          tr.append(td);
        });
        tbody.append(tr);
      });

      table.append(tbody);

      return table;
    },

    // Turns 54321.34 into 54,321.32
    numberWithDelimiter: function (number) {
      var delimiter = ",",
        separator = ".",
        parts = number.toString().split('.'),
        delimitedWholeNumber = this.wholeNumberWithDelimiter(parts[0], delimiter);

      if (parts.length === 2) {
        return [delimitedWholeNumber, parts[1]].join(separator);
      } else {
        return delimitedWholeNumber;
      }
    },

    // Convert whole number 12345 to 12,345
    wholeNumberWithDelimiter: function (wholeNumber, delimiter) {
      var wholeNumberAsString = wholeNumber.toString(),
        lastThreeMatch = wholeNumberAsString.match(/\d{3}$/),
        triads = [],
        wholeNumberStringRemainder = '';

      if (wholeNumber < 1000) {
        return wholeNumber.toString();
      }

      if (lastThreeMatch) {
        triads.unshift(lastThreeMatch[0]);

        // trim last three off string
        wholeNumberStringRemainder = wholeNumberAsString.substr(0, wholeNumberAsString.length - 3);

        if (wholeNumberStringRemainder.length > 3) {
          // recurse
          triads.unshift(this.wholeNumberWithDelimiter(wholeNumberStringRemainder, delimiter));
        } else {
          triads.unshift(wholeNumberStringRemainder);
        }
        return triads.join(delimiter);
      }
    },

    deepClone: function (originalObject) {
      var blankObject = (jQuery.isArray(originalObject) ? [] : {});
      return jQuery.extend(true, blankObject, originalObject);
    },

    // Turns a date into 'October 21, 2010'
    formatDate: function (dateObj, isAllDay) {
      var month = (isAllDay ? dateObj.getUTCMonth() : dateObj.getMonth()),
        date = (isAllDay ? dateObj.getUTCDate() : dateObj.getDate()),
        dayOfWeek = (isAllDay ? dateObj.getUTCDay() : dateObj.getDay()),
        dayOfWeekString = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday"][dayOfWeek],
        monthString = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December"][month];
      return dayOfWeekString + ", " + monthString + " " + date;
    },

    // Parses a Ruby-formatted JSON String:
    //   2010-12-03T17:09:00+00:00
    dateFromDateTimeString: function (dateAsString) {
      var ymdDelimiter = '-',
        pattern = new RegExp("(\\d{4})" + ymdDelimiter + "(\\d{2})" + ymdDelimiter + "(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})");
      var parts = dateAsString.match(pattern);

      return new Date(Date.UTC(
      parseInt(parts[1]), parseInt(parts[2], 10) - 1, parseInt(parts[3], 10), parseInt(parts[4], 10), parseInt(parts[5], 10), parseInt(parts[6], 10), 0));
    },

    // Takes a number of seconds and returns an hour:minute string.
    // Example:
    //   4:02
    //
    secondsToTimeString: function (seconds) {
      var secondsInt = parseInt(seconds, 10),
        hours = parseInt(secondsInt / 60 / 60, 10),
        minutes = parseInt((secondsInt / 60) % 60, 10),
        timeString = '' + (hours > 0 ? hours : '') + ':' + (minutes > 9 ? minutes : '0' + minutes);

      return timeString;
    },

    // Takes a number of seconds and returns an hour:minute string,
    // marked up with HTML tags.
    //
    // Example:
    //   <span class="hour">4</span><span class="minute">02</span>
    //
    secondsToMarkup: function (seconds) {
      var secondsInt = parseInt(seconds, 10),
        hours = parseInt(secondsInt / 60 / 60, 10),
        minutes = parseInt((secondsInt / 60) % 60, 10),
        hoursMarkup = '<span class="hours">' + (hours > 0 ? hours : '&nbsp;') + '</span>',
        minutesMarkup = '<span class="minutes">' + (minutes > 9 ? minutes : '0' + minutes) + '</span>',
        timeMarkup = '' + hoursMarkup + minutesMarkup;

      return timeMarkup;
    }

  }
});

