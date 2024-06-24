'use strict';
/**
 * cb2fa-admin.js
 * Copyright (C) 2024 Joaquim Homrighausen <joho@webbplatsen.se>
 * Development sponsored by WebbPlatsen i Sverige AB, www.webbplatsen.se
 *
 * This file is part of Cloudbridge 2FA. Cloudbridge 2FA is free software.
 *
 * You may redistribute it and/or modify it under the terms of the
 * GNU General Public License version 2, as published by the Free Software
 * Foundation.
 *
 * Cloudbridge 2FA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the Cloudbridge 2FA package. If not, write to:
 *  The Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02110-1301, USA.
 */
var formTabE = null;

var cb2faAllTabs, cb2faAllTabContent;

/* Used to create event handlers with better context (for strict)*/
function cb2faPartial(fn, arg) {
    return function() {
        return (fn.call(this, arg));
    };
}

/* Toggle settings tabs*/
function cb2faSettingTabClick(e) {
    /*console.log(e);*/
    if (! e.classList.contains('nav-tab-active')) {
        Array.from(cb2faAllTabs).forEach(function(tab) {
            tab.classList.remove('nav-tab-active');
        });
        Array.from(cb2faAllTabContent).forEach(function(tab) {
            tab.classList.remove('cb2fa-is-visible-block');
            tab.classList.add( 'cb2fa-is-hidden' );
        });
        e.classList.add('nav-tab-active');
        let linkAnchor = e.getAttribute('data-toggle');
        var visibleBlock = document.getElementById(linkAnchor);
        if (visibleBlock !== null) {
            visibleBlock.classList.add('cb2fa-is-visible-block');
            visibleBlock.classList.remove('cb2fa-is-hidden');
            if (formTabE !== null ) {
                formTabE.value = e.href.substring(e.href.indexOf("#")+1);
            }
        } else {
            console.log('Unable to fetch ID for '+e.getAttribute('data-toggle'));
        }
    }
}

function selectAllExportText(e) {
    e.target.select();
    e.target.focus();
}

/* Make tab visible */
function cb2faShowTab(e) {
    if (e != null) {
        e.classList.add('nav-tab-active');
        let visibleBlock = document.getElementById(e.getAttribute('data-toggle'));
        if (visibleBlock !== null) {
            visibleBlock.classList.add('cb2fa-is-visible-block');
            visibleBlock.classList.remove('cb2fa-is-hidden');
        } else {
            console.log('Unable to fetch ID for '+e.getAttribute('data-toggle'));
        }
    }
}

/* Copy export text to clipboard */
function copyTextToClipboard(e) {
    let t = document.getElementById('cb2fa-textarea-export');
    let m = document.getElementById('cb2facfgexport-success');
    if (m) {
        m.classList.add('cb2fa-is-hidden');
    }
    m = document.getElementById('cb2facfgexport-fail');
    if (m) {
        m.classList.add('cb2fa-is-hidden');
    }
    if (t) {
        t.select();
        t.setSelectionRange(0, 99999);
        navigator.clipboard
            .writeText(t.value)
            .then(() => {
                let m = document.getElementById('cb2facfgexport-success');
                if (m) {
                    m.classList.remove('cb2fa-is-hidden');
                }
            })
            .catch(() => {
                let m = document.getElementById('cb2facfgexport-fail');
                if (m) {
                    m.classList.remove('cb2fa-is-hidden');
                }
            });
    }
}

/* Initialize stuff when DOM is ready*/
var cb2faSetup = function(){
    cb2faAllTabs = document.getElementsByClassName('cb2fa-tab');
    cb2faAllTabContent = document.getElementsByClassName('cb2fa-tab-content');
    formTabE = document.getElementById('cb2fa-form-tab');//Allow form override
    let isFirstTab = true;
    let firstElement = null;
    let formTabV = '';
    if (formTabE !== null) {
        formTabV = formTabE.value;
    }
    /*console.log(window.location);*/
    Array.from(cb2faAllTabs).forEach(function(e) {
        if (firstElement === null) {
            firstElement = e;
        }
        e.addEventListener('click', cb2faPartial(cb2faSettingTabClick, e));
        if (formTabE !== null) {
            if (isFirstTab) {
                if (('#' + formTabV) === e.hash) {
                    cb2faShowTab(e);
                    isFirstTab = false;
                }
            }
        } else if (! window.location.hash) {
            if (isFirstTab) {
                cb2faShowTab(e);
                isFirstTab = false;
            }
        } else if (window.location.hash === e.hash) {
            cb2faShowTab(e);
            isFirstTab = false;
        }
    });

    if (isFirstTab) {
        cb2faShowTab(firstElement);
    }
    let e = document.getElementById('cb2fa-textarea-export');
    if (e) {
        e.addEventListener('click', selectAllExportText);
    }
    e = document.getElementById('cb2fa-textarea-import');
    if (e) {
        e.focus();
    }
    e = document.getElementById('cb2facfgdoexport');
    if (e) {
        e.addEventListener('click', copyTextToClipboard);
    }
};

/* Make sure we are ready */
if (document.readyState === "complete" ||
        (document.readyState !== "loading" && !document.documentElement.doScroll)) {
    cb2faSetup();
} else {
    document.addEventListener("DOMContentLoaded", cb2faSetup);
}
