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

function renderError(elem, errs) {
    $(elem).empty();
    for (err of errs) {
        console.log(
            `<p class='note ${err.noteType}'><strong>${err.pretext}</strong>: ${err.value}</p>`
        );
        $(elem).append(
            `<p class='note ${err.noteType}'><strong>${err.pretext}</strong>: ${err.value}</p>`
        );
    }
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

// The entity map for escaping unsafe characters
let entityMap = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "/": "&#x2F;",
    "`": "&#x60;",
    "=": "&#x3D;",
};

// Uses entityMap to filter out the characters and prevent XSS
function escapeHtml(string) {
    return String(string).replace(/[&<>"'`=\/]/g, function (s) {
        return entityMap[s];
    });
}

// Initialize Trumbowyg
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

// Handle attachment deletion queue
let toBeDeletedAttachments = [];
$(".deleteAttachmentBtn").click(function () {
    let attachmentName = $(this)
        .closest(".attachmentEntry")
        .find(".attachmentTitle")
        .first()
        .text();
    console.log($(this).closest("p"));
    if (!toBeDeletedAttachments.includes(attachmentName)) {
        toBeDeletedAttachments.push(attachmentName);
        $(this).removeClass("fa-times-circle");
        $(this).addClass("fa-trash");
        $(this)
            .closest(".attachmentEntry")
            .find(".attachmentTitle")
            .first()
            .addClass("strikethrough");
    } else {
        toBeDeletedAttachments.splice(
            toBeDeletedAttachments.indexOf(attachmentName),
            1
        );
        $(this).addClass("fa-times-circle");
        $(this).removeClass("fa-trash");
        $(this)
            .closest(".attachmentEntry")
            .find(".attachmentTitle")
            .first()
            .removeClass("strikethrough");
    }
    console.log(
        "Array: " + toBeDeletedAttachments + "\nName: " + attachmentName
    );
});

// Handle editing and creating new vulnerabilities
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
    if (toBeDeletedAttachments.length > 0) {
        fData.append("deletionQueue", JSON.stringify(toBeDeletedAttachments));
    }

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
            }
        },
        error: (res, err) => {
            if (res.status == 413) {
                $("#infoDiv").empty();
                $("#infoDiv").append(`
                    <div class='text-dark my-2 mx-1 note note-danger'>
                        <strong>Error </strong>
                        You've reached the upload limit.
                    </div>`);
            } else {
                renderError($.find("#infoDiv")[0], res.responseJSON.msgs);
                $("#infoDiv")[0].scrollIntoView();
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
        "<p><strong>Registration Date: </strong>" +
            new Date($(obj).text()).toUTCString() +
            "</p>"
    );
});

if ($("#vulnDescriptionTab").length) {
    let localVtid = $("#vulnOverviewHeader").attr("vtid");
    const searchParams = new URLSearchParams(window.location.search);
    console.log("VTID: " + localVtid);
    $.ajax({
        type: "POST",
        url: "/vuln/data",
        data: JSON.stringify(
            searchParams.has("token")
                ? { vtid: localVtid, token: searchParams.get("token") }
                : { vtid: localVtid }
        ),
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
            renderError($.find("#infoDiv")[0], res.responseJSON.msgs);
            $("#infoDiv")[0].scrollIntoView();
            //console.log(err);
            //console.log(res.err);
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
            renderError($.find("#infoDiv")[0], res.responseJSON.msgs);
            $("#infoDiv")[0].scrollIntoView();
            //console.log(err);
            //console.log(res.err);
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
                    renderError($.find("#infoDiv")[0], res.responseJSON.msgs);
                    $("#infoDiv")[0].scrollIntoView();
                    //console.log(err);
                    //console.log(res.err);
                },
            });
        });
    });
}

// Load Activity initially and on scroll
if ($("#activityLoader").length) {
    let activityLoader = $("#activityLoader");
    let skipCounter = 0;
    let listEndReached = false;

    function appendVulnActivity(vuln) {
        vuln.vtid = escapeHtml(vuln.vtid);
        vuln.authorName = escapeHtml(vuln.authorName);
        vuln.affectedProduct = escapeHtml(vuln.affectedProduct);
        vuln.affectedFeature = escapeHtml(vuln.affectedFeature);
        vuln.cvss = escapeHtml(vuln.cvss);
        vuln.authorName = escapeHtml(vuln.authorName);

        $("#vulnActivityCol").append(
        `<div class="activityElement my-3 color-white">
            <div class="d-flex flex-column float-start me-3 bg-lprimary rounded activitySection">
                <i onclick="ProcessVote(this)" class="fas fa-arrow-up mx-2 mt-2 handCur voteArrow upvoteArrow ${vuln.ownVote == 'UP' ? 'voteTriggered' : ''}"></i>
                <p class="mx-2 ${vuln.ownVote == 'UP' || vuln.ownVote == 'DOWN' ? 'voteTriggered' : ''} voteScore" style="margin: 0.3em;">${vuln.voteScore || 0}
                </p>
                <i onclick="ProcessVote(this)" class="fas fa-arrow-down mx-2 handCur voteArrow downvoteArrow ${vuln.ownVote == 'DOWN' ? 'voteTriggered' : ''}"></i> 
            </div>
            <div class="ms-5 bg-lprimary rounded">
               <div class="ms-2 activitySection">
                  <div class="pb-1"></div>
                  <a class="color-white" href="/vuln/id/${vuln.vtid}">
                     <h5 class="vtid d-inline">${vuln.vtid}</h5>
                  </a>
                  <a class="color-white" href="user/profile/${vuln.author}">
                     <h5 class="d-inline float-end me-2">${vuln.authorName}
                     </h5>
                  </a>
                  <p class="mt-1">${vuln.affectedProduct} - ${vuln.affectedFeature} - ${vuln.type} (<strong class="cvssScore">${vuln.cvss}</strong>)
                  </p>
               </div>
            </div>
         </div>`
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
                    //console.log(err);
                    //console.log(res.err);
                    if ((res.err = "endReached")) {
                        listEndReached = true;
                    } else {
                        renderError(
                            $.find("#infoDiv")[0],
                            res.responseJSON.msgs
                        );
                        $("#infoDiv")[0].scrollIntoView();
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

// Activity Vote Button Processing (UP, DOWN, CANCEL)

function ProcessVote(voteButton) {
    let voteType = $(voteButton).hasClass('upvoteArrow') ? 'UP' : 'DOWN';
    if ($(voteButton).hasClass('voteTriggered')) {
        voteType = 'CANCEL'
    }
    console.log(voteType);

    function FeedbackProcessor() {
        $(voteButton).addClass('voteTriggered');
        let counter = $(voteButton).parent().find('.voteScore');
        let counterVal = voteType === 'UP' ? 1 : -1;
        $(counter).addClass('voteTriggered');
        $(counter).text(parseInt($(counter).text()) + counterVal);
        let opposite = $(voteButton).parent().find($(voteButton).hasClass('upvoteArrow') ? '.downvoteArrow' : '.upvoteArrow');
        if ($(opposite).hasClass('voteTriggered')) {
            $(opposite).removeClass('voteTriggered');
            $(counter).text(parseInt($(counter).text()) + counterVal);
        }
    }

    let vtid = $(voteButton).parentsUntil('.activityElement').parent().find('.vtid').text();
    $.ajax({
        type: 'POST',
        url: '/activity/processVote',
        data: JSON.stringify({
            vtid: vtid,
            voteType: voteType
        }),
        processData: false,
        contentType: 'application/json',
        success: (res) => {
            
    switch (voteType) {
        case 'UP':
                FeedbackProcessor();
            break;
        case 'DOWN':
                FeedbackProcessor();
            break;
        case 'CANCEL':
                    let upvoteArrow = $(voteButton).hasClass('upvoteArrow') ? $(voteButton) : $(voteButton).parent().find('.upvoteArrow');
                    let downvoteArrow = $(voteButton).hasClass('downvoteArrow') ? $(voteButton) : $(voteButton).parent().find('.upvoteArrow');

                    if ($(upvoteArrow).hasClass('voteTriggered')) {
                        $(upvoteArrow).removeClass('voteTriggered')
                        let counter = $(voteButton).parent().find('.voteScore');
                        $(counter).removeClass('voteTriggered')
                        $(counter).text(parseInt($(counter).text()) - 1);
                    }
                    if ($(downvoteArrow).hasClass('voteTriggered')) {
                        $(downvoteArrow).removeClass('voteTriggered')
                        let counter = $(voteButton).parent().find('.voteScore');
                        $(counter).removeClass('voteTriggered');
                        $(counter).text(parseInt($(counter).text()) + 1);
                    }
                break;
            }
        },
        error: (res, err) => {
            renderError($.find("#infoDiv")[0], res.responseJSON.msgs);
        }
    });
}

// Token Adding
if ($("#expiryDatePicker").length) {
    $("#expiryDatePicker").attr("min", new Date().toISOString().split(".")[0]);
}
if ($("#addTokenBtn").length) {
    $("#addTokenBtn").click(() => {
        $.ajax({
            type: "POST",
            url: "/vuln/share/createToken",
            data: JSON.stringify({
                vtid: $("#scHeader").attr("vtid"),
                expiryDate: $("#expiryDatePicker").val(),
            }),
            processData: false,
            contentType: "application/json",
            success: (res) => {
                location.reload();
            },
            error: (res, err) => {
                renderError($.find("#infoDiv")[0], res.responseJSON.msgs);
                $("#infoDiv")[0].scrollIntoView();
            },
        });
    });
}

// Token Deletion
if ($(".delTokenBtn").length) {
    $(".delTokenBtn").click(function () {
        $.ajax({
            type: "POST",
            url: "/vuln/share/deleteToken",
            data: JSON.stringify({
                vtid: $("#scHeader").attr("vtid"),
                token: $(this).closest("tr").find(".token").text(),
            }),
            processData: false,
            contentType: "application/json",
            success: (res) => {
                if (!res.err) {
                    $(this)
                        .closest("tr")
                        .fadeTo("fast", 0, () => {
                            $(this).closest("tr").remove();
                        });
                }
            },
            error: (res, err) => {
                renderError($.find("#infoDiv")[0], res.responseJSON.msgs);
                $("#infoDiv")[0].scrollIntoView();
            },
        });
    });
}

// Token Timer Calculations
if ($(".tokenCreationDate").length) {
    $(".tokenCreationDate").each((i, obj) => {
        let creationDate = $(obj).text();
        let expiryDate = $(obj).parent().find(".tokenExpiryDate").text();
        let countdownObj = $(obj).parent().find(".tokenTimeLeft");
        console.log(`TokenPair [${creationDate} - ${expiryDate}]`);
        $(countdownObj).attr('time', Date.parse(expiryDate) - Date.now());
        setInterval(() => {
            updateTimer(countdownObj);
        }, 1000);
    });
}

function updateTimer(obj) {
    $(obj).attr("time", $(obj).attr("time") - 1000);
    $(obj).text(humanizeDuration($(obj).attr("time")));
}


// Profile Editing
$("#editProfileForm").submit((e) => {
    let actionUrl = $("#editProfileForm").attr("action");
    e.preventDefault();
    // The FormData object exists here because
    // then additional normal form fields can
    // be added without worrying.
    let fData = new FormData($("#editProfileForm")[0]);
    fData.append("bio", $(".trumbowyg-editor").html());

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
                        Profile modified successfully. Redirecting in 3 seconds...
                    </div>`);
                setTimeout(() => {
                    window.location.href = "/user/profile/edit";
                }, 3000);
            }
        },
        error: (res, err) => {
            renderError($.find("#infoDiv")[0], res.responseJSON.msgs);
            $("#infoDiv")[0].scrollIntoView();
        },
    });
});

// Bio Retrieval for Profiles and Profile Edits
if ($('.bio').length) {
    $.ajax({
        type: "POST",
        url: '/user/profile/bio',
        data: JSON.stringify({uid: $('.bio').attr('uid')}),
        processData: false,
        contentType: "application/json",
        success: (res) => {
            if (res.bio) {
                $(".bio").append(
                    DOMPurify.sanitize(res.bio)
                );
            } else {
                $(".bio").append("<em><strong>Hmm... It seems like nothing is here.</strong></em>")
            }
        },
        err: (err) => {
            console.log(err);
        }
    })
}