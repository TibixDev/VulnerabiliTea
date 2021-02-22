// Sidebar
let mediaQueryPhone = window.matchMedia("(max-width: 480px)");
let mediaQueryTab = window.matchMedia("(max-width: 768px)");
let mediaQueryBigTab = window.matchMedia("(max-width: 1024px)");
let sbCollapsed = true;
let sbModifier = "0vw";
mediaQueryHandler();
mediaQueryPhone.addListener(mediaQueryHandler);
mediaQueryTab.addListener(mediaQueryHandler);
mediaQueryBigTab.addListener(mediaQueryHandler);

function mediaQueryHandler() {
    if (mediaQueryPhone.matches) {
        sbModifier = "100vw";
    } else if (mediaQueryTab.matches) {
        sbModifier = "40vw";
    } else if (mediaQueryBigTab.matches) {
        sbModifier = "30vw";
    } else {
        sbModifier = "20vw";
    }
    sidebarUpdateHandler();
}

function sidebarUpdateHandler() {
    if (!sbCollapsed) {
        $("#sidebar")[0].style.width = sbModifier;
        $(".content")[0].style.marginLeft = sbModifier;
        $("#footer")[0].style.marginLeft = sbModifier;
    }
}

function sidebarHandler() {
    if (sbCollapsed) {
        $("#sidebar")[0].style.width = sbModifier;
        $(".content")[0].style.marginLeft = sbModifier;
        $("#footer")[0].style.marginLeft = sbModifier;
        sbCollapsed = !sbCollapsed;
    } else {
        $("#sidebar")[0].style.width = 0;
        $(".content")[0].style.marginLeft = 0;
        $("#footer")[0].style.marginLeft = 0;
        sbCollapsed = !sbCollapsed;
    }
}

// Helper Functions
function isScrolledIntoView(elem) {
    var docViewTop = $(window).scrollTop();
    var docViewBottom = docViewTop + $(window).height();

    var elemTop = $(elem).offset().top;
    var elemBottom = elemTop + $(elem).height();

    return elemBottom <= docViewBottom && elemTop >= docViewTop;
}

function colorizeCVSS() {
    $(".cvssScore").each((i, obj) => {
        let val = Number($(obj).text());
        if (val >= 9.0) {
            $(obj).addClass("text-danger");
        } else if (val >= 7.0) {
            $(obj).addClass("text-warning");
        } else if (val >= 4.0) {
            $(obj).addClass("text-secondary");
        } else if (val >= 0.1) {
            $(obj).addClass("text-success");
        }
    });
}

let entityMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;'
  };
  
function escapeHtml (string) {
  return String(string).replace(/[&<>"'`=\/]/g, function (s) {
    return entityMap[s];
  });
}

// Everything else
$(() => {
    if ($(".trumbowyg").length) {
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

    $("#vulnForm").submit((e) => {
        let actionUrl = $("#vulnForm").attr("action");
        e.preventDefault();
        let fData = new FormData($("#vulnForm")[0]);
        let modeVerb = "added";
        if (actionUrl.includes("edit")) {
            fData.append("vtid", $("#vulnEditHeader").attr("vtid"));
            modeVerb = "modified";
        }
        fData.append("description", $(".trumbowyg-editor").html());

        $.ajax({
            type: "POST",
            url: actionUrl,
            data: fData,
            processData: false,
            contentType: false,
            success: (res) => {
                if (res.status == "success") {
                    $("#infoDiv").empty();
                    $("#infoDiv").append(`
                    <div class='text-dark my-2 mx-1 note note-success'>
                        <strong>Success</strong>
                        Vulnerability ${modeVerb} successfully. Redirecting in 3 seconds...
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
            error: (res, err) => {
                if (res.status == 413) {
                    $("#infoDiv").empty();
                    $("#infoDiv").append(`
                    <div class='text-dark my-2 mx-1 note note-danger'>
                        <strong>Error </strong>
                        You've reached the upload limit of 50MB.
                    </div>`);
                }
            },
        });
    });

    colorizeCVSS();

    $(".status").each((i, obj) => {
        let statusStr = $(obj).text();
        if (statusStr.includes("Patched")) {
            $(obj).addClass("text-success");
        } else if (statusStr.includes("Reported")) {
            $(obj).addClass("text-warning");
        } else if (statusStr.includes("Unpatched")) {
            $(obj).addClass("text-danger");
        }
    });

    $(".dateReported").each((i, obj) => {
        $(obj).text(new Date($(obj).text()).toUTCString());
    });

    $(".regDate").each((i, obj) => {
        $(obj).html(
            "<p><strong>Register Date: </strong>" +
                new Date($(obj).text()).toUTCString() +
                "</p>"
        );
    });

    if ($("#vulnDescriptionTab").length) {
        let localVtid = $("#vulnOverviewHeader").attr("vtid");
        console.log("VTID: " + localVtid);
        $.ajax({
            type: "POST",
            url: "/vuln/data",
            data: JSON.stringify({ vtid: localVtid }),
            processData: false,
            contentType: "application/json",
            success: (res) => {
                console.log(res);
                if (!res.err) {
                    $("#vulnDescriptionTab").append(
                        DOMPurify.sanitize(res.vuln.description)
                    );
                }
            },
            error: (res, err) => {
                console.log(err);
                console.log(res.err);
            },
        });
    }

    /* This applies values the droptowns too, but I don't want to 
       make 2 separate ifs because it's long and ugly */
    if ($("#vulnDescEdit").length) {
        let localVtid = $("#vulnEditHeader").attr("vtid");
        console.log("VTID: " + localVtid);
        $.ajax({
            type: "POST",
            url: "/vuln/data",
            data: JSON.stringify({ vtid: localVtid }),
            processData: false,
            contentType: "application/json",
            success: (res) => {
                console.log(res);
                if (!res.err) {
                    $("#vulnDescEdit").append(
                        DOMPurify.sanitize(res.vuln.description)
                    );
                    $(`select option[value='${res.vuln.type}']`).attr(
                        "selected",
                        "selected"
                    );
                    $(`select option[value='${res.vuln.status}']`).attr(
                        "selected",
                        "selected"
                    );
                    $("#publicBox").prop("checked", res.vuln.public);
                }
            },
            error: (res, err) => {
                console.log(err);
                console.log(res.err);
            },
        });
    }

    if ($(".vulnDeleteBtn").length) {
        $(".vulnDeleteBtn").each((i, obj) => {
            $(obj).click(() => {
                $.ajax({
                    type: "DELETE",
                    url: "/vuln/delete",
                    data: JSON.stringify({ vtid: $(obj).attr("vtid") }),
                    processData: false,
                    contentType: "application/json",
                    success: (res) => {
                        if (!res.err) {
                            $(obj)
                                .closest("tr")
                                .fadeTo("fast", 0, () => {
                                    $(obj).closest("tr").remove();
                                });
                        }
                    },
                    error: (res, err) => {
                        console.log(err);
                        console.log(res.err);
                    },
                });
            });
        });
    }

    if ($("#activityLoader").length) {
        let activityLoader = $("#activityLoader");
        let skipCounter = 0;
        let listEndReached = false;

        function appendVulnActivity(vuln) {
            vuln.vtid = escapeHtml(vuln.vtid);
            vuln.author = escapeHtml(vuln.author);
            vuln.affectedProduct = escapeHtml(vuln.affectedProduct);
            vuln.affectedFeature = escapeHtml(vuln.affectedFeature);
            vuln.cvss = escapeHtml(vuln.cvss);

            $("#vulnActivityCol").append(
                `<div class="activityElement my-3 color-white"> <div class="d-flex flex-column float-start me-3 bg-primary rounded activitySection"><i class="fas fa-arrow-up mx-2 mt-2 upvoteArrow"></i> <p class="mx-2" style="margin: 0.3em;">${
                    vuln.communityScore || 0
                }</p><i class="fas fa-arrow-down mx-2 downvoteArrow"></i> </div><div class="ms-5 bg-primary rounded"> <div class="ms-2 activitySection"> <div class="pb-1"></div><a class="color-white" href="/vuln/id/${
                    vuln.vtid
                }"><h5 class="d-inline">${
                    vuln.vtid
                }</h5></a><a class="color-white" href="/profile/${
                    vuln.author
                }"><h5 class="d-inline float-end me-2">${
                    vuln.author
                }</h5></a><p class="mt-1">${vuln.affectedProduct} - ${
                    vuln.affectedFeature
                } - ${vuln.type} (<strong class="cvssScore">${
                    vuln.cvss
                }</strong>)</p></div></div></div>`
            );
            colorizeCVSS();
        }

        function getNewActivityEntries() {
            if (!listEndReached) {
                $.ajax({
                    type: "POST",
                    url: "/activity/getActivity",
                    data: JSON.stringify({ skipCount: skipCounter }),
                    processData: false,
                    contentType: "application/json",
                    success: (res) => {
                        if (!res.err) {
                            for (vuln of res.vulns) {
                                console.log(vuln);
                                appendVulnActivity(vuln);
                                skipCounter++;
                            }
                        }
                    },
                    error: (res, err) => {
                        console.log(err);
                        console.log(res.err);
                        if ((res.err = "endReached")) {
                            listEndReached = true;
                        }
                    },
                });
            }
        }

        getNewActivityEntries();

        $(window).scroll(() => {
            if (isScrolledIntoView(activityLoader)) {
                getNewActivityEntries();
            }
        });
    }
});
