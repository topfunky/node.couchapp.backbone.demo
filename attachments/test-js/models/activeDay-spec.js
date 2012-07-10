describe("app.models.activeDay", function () {

  it("defaults to today", function () {
    var d = app.models.activeDay,
      today = new Date();

    expect(d.get('name')).toEqual(today.strftime('%A'));
  });

  it("sets date from string argument", function () {
    var d = app.models.activeDay;
    d.setFromDateString('2011-03-21');

    expect(d.get('name')).toEqual('Monday');
  });

  it("switches to previous day", function () {
    var d = app.models.activeDay,
      previousDate = null;
    d.setFromDateString('2011-03-21');
    previousId = d.previousId();

    expect(previousId).toEqual('2011-03-20');
  });

  it("switches to next day", function () {
    var d = app.models.activeDay,
      nextDate = null;
    d.setFromDateString('2011-03-31');
    nextId = d.nextId();

    expect(nextId).toEqual('2011-04-01');
  });

});
