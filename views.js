var views = module.exports = exports = {};

views.by_collection = {
  map: function (doc) {
    if (doc.collection) {
      emit(doc.collection, doc);
    }
  }
};

views.by_event = {
  map: function (doc) {
    if (doc.collection && doc.collection == 'event' && doc.date) {
      emit(doc.date, doc);
    }
  }
};

views.by_event_title = {
  map: function (doc) {
    if (doc.collection && doc.collection == 'event' && doc.date) {
      emit([doc.date, doc.completedAt, doc.title], doc);
    }
  }
};

views.tag_report_by_day = {
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

views.uncompleted_events = {
  map: function (doc) {
    if (doc.collection && doc.collection == 'event' && !doc.completedAt) {
      emit(doc.date, doc);
    }
  }
};
