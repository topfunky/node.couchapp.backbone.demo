var views = module.exports = exports = {};

views.byCollection = {
  map: function (doc) {
    if (doc.collection) {
      emit(doc.collection, doc);
    }
  }
};

views.byEvent = {
  map: function (doc) {
    if (doc.collection && doc.collection == 'event' && doc.date) {
      emit(doc.date, doc);
    }
  }
};

views.byEventTitle = {
  map: function (doc) {
    if (doc.collection && doc.collection == 'event' && doc.date) {
      emit([doc.date, doc.completedAt, doc.title], doc);
    }
  }
};

views.tagReportByDay = {
  map: function (doc) {
    if (doc.collection && doc.collection == 'event' && doc.durationSeconds) {
      emit([doc.date, (doc.tag || 'other')], doc.durationSeconds);
    }
  },
  reduce: function (keys, values, rereduce) {
    // TODO: Run with group_level=2
    // Returns: 
    //   { durationSeconds: 123, tag: 'bacon' }
    return {
      durationSeconds: sum(values),
      tag: keys[0][0][1]
    };
  }
};

views.uncompletedEvents = {
  map: function (doc) {
    if (doc.collection && doc.collection == 'event' && !doc.completedAt) {
      emit(doc.date, doc);
    }
  }
};
