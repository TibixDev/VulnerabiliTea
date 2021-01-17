// Sidebar
let mediaQueryPhone = window.matchMedia("(max-width: 480px)");
let mediaQueryTab = window.matchMedia("(max-width: 768px)");
let mediaQueryBigTab = window.matchMedia("(max-width: 1024px)");
let sbCollapsed = true;
let sbModifier = '0vw';
mediaQueryHandler();
mediaQueryPhone.addListener(mediaQueryHandler);
mediaQueryTab.addListener(mediaQueryHandler);
mediaQueryBigTab.addListener(mediaQueryHandler);

function mediaQueryHandler() {
    if (mediaQueryPhone.matches) {
        sbModifier = '100vw'
    } else if (mediaQueryTab.matches) {
        sbModifier = '40vw';
    } else if (mediaQueryBigTab.matches) {
        sbModifier = '30vw';
    } else {
        sbModifier = '20vw';
    }
    sidebarUpdateHandler();
}

function sidebarUpdateHandler() {
    if (!sbCollapsed) {
        $('#sidebar')[0].style.width = sbModifier;
        $('.content')[0].style.marginLeft = sbModifier;
        $('#footer')[0].style.marginLeft = sbModifier;
    }
}

function sidebarHandler() {
    if (sbCollapsed) {
        $('#sidebar')[0].style.width = sbModifier;
        $('.content')[0].style.marginLeft = sbModifier;
        $('#footer')[0].style.marginLeft = sbModifier;
        sbCollapsed = !sbCollapsed;
    } else {
        $('#sidebar')[0].style.width = 0;
        $('.content')[0].style.marginLeft = 0;
        $('#footer')[0].style.marginLeft = 0;
        sbCollapsed = !sbCollapsed;
    }
}

$(() => {
    if ($(".trumbowyg")) {
        $.trumbowyg.svgPath = "/res/trumbowyg/icos/icons.svg";
        $(".trumbowyg").trumbowyg({
            btns: [
                ["viewHTML"],
                ["undo", "redo"], // Only supported in Blink browsers
                ["formatting"],
                ["strong", "em", "del"],
                ["fontsize", "fontfamily"],
                ["foreColor", "backColor"],
                ["superscript", "subscript"],
                ["link"],
                ["insertImage"],
                ["justifyLeft", "justifyCenter", "justifyRight", "justifyFull"],
                ["unorderedList", "orderedList"],
                ["horizontalRule"],
                ["removeformat"],
                ["fullscreen"],
                ["indent", "outdent"],
                ["table"],
            ],
        });
    }

    $("#vulnAddForm").submit((e) => {
        e.preventDefault();
        let fData = new FormData($("#vulnAddForm")[0]);
        fData.append("description", $(".trumbowyg-editor").html());
        $.ajax({
            type: "POST",
            url: "/vuln/add",
            data: fData,
            processData: false,
            contentType: false,
            success: res => {
                if (res.status == "success") {
                    $("#infoDiv").append(`
                    <div class='text-dark my-2 mx-1 note note-success'>
                        <strong>Success</strong>
                        Vulnerability added successfully. Redirecting in 3 seconds...
                    </div>`);
                    setTimeout(() => {
                        window.location.href = "/vuln";
                    }, 3000);
                } else {
                    $("#infoDiv").empty();
                    for (msg of res.msgs) {
                        $("#infoDiv").append(`
                            <div class='text-dark my-2 mx-1 note ${msg.noteType}'>
                                <strong>${msg.pretext}</strong>
                                ${msg.value}
                            </div>`);
                    }
                    $("#infoDiv")[0].scrollIntoView();
                }
            },
        });
    });

    $('.cvssScore').each((i, obj) => {
        let val = Number($(obj).text());
        if (val >= 9.0) {
            $(obj).addClass('text-danger');
        }
        else if (val >= 7.0) {
            $(obj).addClass('text-warning');
        }
        else if (val >= 4.0) {
            $(obj).addClass('text-secondary');
        }
        else if (val >= 0.1) {
            $(obj).addClass('text-success');
        }
    });

    $('.status').each((i, obj) => {
        let statusStr = $(obj).text();
        if (statusStr.includes('Patched')) {
            $(obj).addClass('text-success');
        }
        else if (statusStr.includes('Reported')) {
            $(obj).addClass('text-warning');
        }
        else if (statusStr.includes('Unpatched')) {
            $(obj).addClass('text-danger');
        }
    });

    $('.dateReported').each((i, obj) => {
        $(obj).text(new Date($(obj).text()).toUTCString());
    });
    $('.regDate').each((i, obj) => {
        $(obj).html("<p><strong>Register Date: </strong>" + new Date($(obj).text()).toUTCString() + "</p>");
    });
});
