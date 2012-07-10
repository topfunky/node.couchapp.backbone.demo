describe("app.util", function() {

  beforeEach(function() {

  });

  it("parses date", function () {
    var date = app.util.dateFromDateTimeString('2010-12-03T17:09:00+00:00');

    expect(date.getUTCMonth()).toEqual(11);
    expect(date.getUTCFullYear()).toEqual(2010);
    expect(date.getUTCDate()).toEqual(03);

    expect(date.getUTCHours()).toEqual(17);
    expect(date.getUTCMinutes()).toEqual(09);
    expect(date.getUTCSeconds()).toEqual(00);
  });

  it("formats seconds as string", function () {
    var seconds = 14520;

    expect(app.util.secondsToTimeString(seconds)).toEqual("4:02");
  });

});


