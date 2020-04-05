const client = new dhive.Client('https://api.hive.blog');

// Generates Aall Private Keys from username and password
function getPrivateKeys(username, password, roles = ['owner', 'active', 'posting', 'memo']) {
  const privKeys = {};
  roles.forEach((role) => {
    privKeys[role] = dhive.PrivateKey.fromLogin(username, password, role).toString();
    privKeys[`${role}Pubkey`] = dhive.PrivateKey.from(privKeys[role]).createPublic().toString();
  });

  return privKeys;
};

// Creates a suggested password
function suggestPassword() {
  const array = new Uint32Array(10);
  window.crypto.getRandomValues(array);
  return 'P' + dhive.PrivateKey.fromSeed(array).toString();
}

// Getting public owner key from username and password
function getPublicOwnerKey(username, password) {
  return (getPrivateKeys(username, password, ['owner'])).ownerPubkey;
}

// Checks if an account is eligible for recovery
async function checkEligibility(username) {
  const [account] = await client.database.getAccounts([username]);
  const now = new Date();
  const lastUpdate = new Date(`${account.last_owner_update}Z`);

  return ((now.getTime() - lastUpdate.getTime()) < (86400000 * 30));
}

$(document).ready(async function () {

  // Auto fills password field
  $('#new-password').val(suggestPassword());
  $('#regen-password').click(function (e) {
    e.preventDefault();
    $(this).closest('.input-group').find('#new-password').val(suggestPassword());
    $('#public-owner-key').val('');
  });

  // Processing Owner key form
  $('#get-owner-key').submit(async function (e) {
    e.preventDefault();

    const feedback = $('#alert-get-owner-key');
    const username = $('#atr').val();
    const password = $('#new-password').val();

    if (username === '') {
      $('#atr').focus();
    } else {
      const isEligible = await checkEligibility(username);

      if (isEligible) {
        feedback.empty().removeClass('alert-warning');
        $('#public-owner-key').addClass('is-valid').val(getPublicOwnerKey(username, password));
      } else {
        $('#public-owner-key').removeClass('is-valid').val('');
        feedback.addClass('alert-warning');
        feedback.html(`Owner authority of <strong>${username}</strong> has not changed in last 30 days!`);
      }
    }
  });

  // Processing create recovery request form
  $('#create-recovery-request').submit(async function (e) {
    e.preventDefault();

    const feedback = $('#alert-create-recovery');
    const username = $('#trustee-atr').val();
    const ownerPubKey = $('#atr-new-key').val();
    const trustee = $('#trustee-account').val();
    const activeKey = $('#trustee-key').val();


    if (username === '') {
      $('#trustee-atr').focus();
    } else {
      feedback.empty().removeClass('alert-success').removeClass('alert-warning');

      const isEligible = await checkEligibility(username);

      if (isEligible) {
        const op = ['request_account_recovery', {
          recovery_account: trustee,
          account_to_recover: username,
          new_owner_authority: dhive.Authority.from(ownerPubKey),
          extensions: []
        }];

        if (activeKey === '') {
          if (window.hive_keychain) {
            window.hive_keychain.requestBroadcast(trustee, [op], 'active', function (response) {
              if (response.success) {
                feedbackDiv.addClass('alert-success').text(`Account recovery request for <strong>${username}</strong> has been submitted successfully.`);
              } else {
                feedbackDiv.addClass('alert-danger').text(response.message);
              }
            });
          } else {
            alert('Hive Keychain is not installed.');
          }
        } else {
          client.broadcast.sendOperations([op], dhive.PrivateKey.from(activeKey))
            .then((r) => {
              console.log(r);
              feedback.addClass('alert-success').html(`Account recovery request for <strong>${username}</strong> has been submitted successfully.`);
            })
            .catch(e => {
              console.log(e);
              feedback.addClass('alert-danger').text(e.message);
            });
        }
      } else {
        feedback.addClass('alert-warning');
        feedback.html(`Owner authority of <strong>${username}</strong> has not changed in last 30 days!`);
      }
    }
  });

  // Processing recover account form
  $('#recover-account').submit(async function (e) {
    e.preventDefault();

    const feedback = $('#alert-recover-account');
    const username = $('#user-atr').val();
    const newPassword = $('#user-new-pass').val();
    const oldPassword = $('#user-old-pass').val();


    if (username === '') {
      $('#user-atr').focus();
    } else {
      feedback.empty().removeClass('alert-success').removeClass('alert-warning').removeClass('alert-danger');

      const isEligible = await checkEligibility(username);

      if (isEligible) {

        const newOwner = getPrivateKeys(username, newPassword, ['owner']);
        const oldOwner = getPrivateKeys(username, oldPassword, ['owner']);

        const op = ['recover_account', {
          account_to_recover: username,
          new_owner_authority: dhive.Authority.from(newOwner.ownerPubkey),
          recent_owner_authority: dhive.Authority.from(oldOwner.ownerPubkey),
          extensions: []
        }
        ];

        // Signing the operation with both old and new owner key
        client.broadcast.sendOperations([op], [dhive.PrivateKey.from(oldOwner.owner), dhive.PrivateKey.from(newOwner.owner)])
          .then((r) => {
            console.log(r);
            feedback.addClass('alert-success').html(`<strong>${username}</strong> has been recovered successfully.</strong>`);
          })
          .catch(e => {
            console.log(e);
            feedback.addClass('alert-danger').text(e.message);
          });
      } else {
        feedback.addClass('alert-warning');
        feedback.html(`Owner authority of <strong>${username}</strong> has not changed in last 30 days!`);
      }
    }
  });

  // Processing change recovery account form
  $('#change-recovery-account').submit(async function (e) {
    e.preventDefault();

    const feedback = $('#alert-change-rec');
    const username = $('#change-rec-atr').val();
    const newRecovery = $('#change-rec-new').val();
    const password = $('#change-rec-pass').val();

    feedback.empty().removeClass('alert-success').removeClass('alert-danger');

    if (username !== '' && newRecovery !== '' && password !== '') {
      const op = ['change_recovery_account', {
        account_to_recover: username,
        new_recovery_account: newRecovery,
        extensions: [],
      }];

      const ownerKey = getPrivateKeys(username, password, ['owner']);

      client.broadcast.sendOperations([op], dhive.PrivateKey.from(ownerKey.owner))
        .then((r) => {
          console.log(r);
          feedback.addClass('alert-success').html(`Change account recovery request for <strong>${username}</strong> has been submitted successfully. It would take 30 days to take effect.`);
        })
        .catch(e => {
          console.log(e);
          feedback.addClass('alert-danger').text(e.message);
        });
    }
  });
});

