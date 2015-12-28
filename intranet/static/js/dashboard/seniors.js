function getTimeRemaining(endtime){
  var t = Date.parse(endtime) - Date.parse(new Date());
  var seconds = Math.floor( (t/1000) % 60 );
  var minutes = Math.floor( (t/1000/60) % 60 );
  var hours = Math.floor( (t/(1000*60*60)) % 24 );
  var days = Math.floor( t/(1000*60*60*24) );
  return {
    'total': t,
    'days': days,
    'hours': hours,
    'minutes': minutes,
    'seconds': seconds
  };
}

function initClock(id, evt, endtime){
  var clock = document.querySelector(id);

  function updateClock(){
    var t = getTimeRemaining(endtime);

    var dys = t.days;
    var hrs = t.hours;
    var mns = t.minutes;
    var scs = ('0' + t.seconds).slice(-2);

    if(dys > 14) {
        clock.innerHTML = "<b>"+dys+"</b> days until " + evt;
    } else {
        clock.innerHTML = "<b>"+dys+"</b> days, <b>"+hrs+"</b> hours, <b>"+mns+"</b> minutes until " + evt;
    }

    if(t.total<=0){
      clearInterval(timeinterval);
      clock.innerHTML = "<span style='color: red'>YOU HAVE GRADUATED!</span>";
    }
  }

  updateClock();
  var timeinterval = setInterval(updateClock, 10000);
}

$(function() {
    var graddate = $(".seniors-widget").attr("data-graduation-date");
    var deadline = graddate + " GMT-0400 (EDT)";
    initClock(".seniors-clock", "Graduation!", deadline);
});