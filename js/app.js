const client = new dhive.Client('https://api.hive.blog', 'https://api.deathwing.me', 'https://rpc.ecency.com', 'https://hive-api.arcange.eu', 'https://rpc.mahdiyari.info');

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

      const recoveryRequest = await client.database.call('get_recovery_request', [username])

      if (recoveryRequest && new Date(`${recoveryRequest.expires}Z`).getTime() > new Date().getTime()) {

        const newOwner = getPrivateKeys(username, newPassword, ['owner', 'active', 'posting', 'memo']);
        const oldOwner = getPrivateKeys(username, oldPassword, ['owner']);

        const op = ['recover_account', {
          account_to_recover: username,
          new_owner_authority: dhive.Authority.from(newOwner.ownerPubkey),
          recent_owner_authority: dhive.Authority.from(oldOwner.ownerPubkey),
          extensions: []
        }];

        const [account] = await client.database.getAccounts([username]);

        const accountUpdateObj = {
          account: username,
          active: dhive.Authority.from({ weight_threshold: account.active.weight_threshold, account_auths: account.active.account_auths, key_auths: [[newOwner.activePubkey, 1]] }),
          posting: dhive.Authority.from({ weight_threshold: account.posting.weight_threshold, account_auths: account.posting.account_auths, key_auths: [[newOwner.postingPubkey, 1]] }),
          memo_key: newOwner.memoPubkey,
          json_metadata: account.json_metadata,
        };

        // Signing the operation with both old and new owner key
        client.broadcast.sendOperations([op], [dhive.PrivateKey.from(oldOwner.owner), dhive.PrivateKey.from(newOwner.owner)])
          .then(async (r) => {
            console.log(r);
            feedback.addClass('alert-success').html(`<strong>${username}</strong> has been recovered successfully.</strong>`);

            // Updating account with the new posting and active key
            client.broadcast.updateAccount(accountUpdateObj, dhive.PrivateKey.from(newOwner.owner))
              .then(async (r) => {
                console.log(r);
              })
              .catch(e => {
                console.log(e);
              });
          })
          .catch(e => {
            console.log(e);
            feedback.addClass('alert-danger').text(e.message);
          });
      } else {
        feedback.addClass('alert-warning').html(`Unable to find recovery request for <strong>${username}</strong> or the request has expired. Please start the procedure again.`);
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

  // Processing change keys form
  $('#change-keys').submit(async function (e) {
    e.preventDefault();

    const feedback = $('#alert-change-keys');
    const username = $('#hive-username').val().toLowerCase()

    const keys = {
      'Owner Key': $('#public-owner-key').val(),
      'Active Key': $('#public-active-key').val(),
      'Posting Key': $('#public-posting-key').val(),
      'Memo Key': $('#public-memo-key').val(),
    }

    const privOwnerKey = $('#private-owner-key').val();

    feedback.removeClass('alert-danger alert-success').empty()

    if (!dhive.cryptoUtils.isWif(privOwnerKey)) {
      feedback.addClass('alert-danger').text('Invalid current private owner key.');
      return
    }

    let validPubKey = true

    const regex = new RegExp('^STM[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{50}$')

    const keyTypes = Object.keys(keys)

    for (let i = 0; i < keyTypes.length; i += 1) {
      const k = keyTypes[i];

      if (!regex.test(keys[k])) {
        feedback.addClass('alert-danger').text(`Invalid public ${k}.`);
        validPubKey = false

        break;
      }
    }

    if (validPubKey) {
      const [account] = await client.database.getAccounts([username])

      if (!account) {
        feedback.addClass('alert-danger').text(`Invalid Hive username: ${username}.`);

        return
      }


      const ownerKey = dhive.PublicKey.fromString(keys['Owner Key']);
      const activeKey = dhive.PublicKey.fromString(keys['Active Key']);
      const postingKey = dhive.PublicKey.fromString(keys['Posting Key']);
      const memoKey = dhive.PublicKey.fromString(keys['Memo Key']);


      const ownerAuth = new dhive.Authority({
        weight_threshold: account.owner.weight_threshold,
        account_auths: account.owner.account_auths,
        key_auths: [[ownerKey, 1]]
      })

      const activeAuth = new dhive.Authority({
        weight_threshold: account.active.weight_threshold,
        account_auths: account.active.account_auths,
        key_auths: [[activeKey, 1]]
      })

      const postingAuth = new dhive.Authority({
        weight_threshold: account.posting.weight_threshold,
        account_auths: account.posting.account_auths,
        key_auths: [[postingKey, 1]]
      })

      const op = ["account_update", {
        "account": account.name,
        "owner": ownerAuth,
        "active": activeAuth,
        "posting": postingAuth,
        "memo_key": memoKey,
        "json_metadata": account.json_metadata
      }]

      client.broadcast.sendOperations([op], dhive.PrivateKey.from(privOwnerKey))
        .then((r) => {
          console.log(r);
          feedback.addClass('alert-success').html(`Successfully updated keys for <strong>${username}</strong>.`);
        })
        .catch(e => {
          console.log(e);
          feedback.addClass('alert-danger').text(e.message);
        });
    }
  });
});

const voteHiveWitness = () => {
  if (window.hive_keychain) {
    window.hive_keychain.requestWitnessVote(null, 'reazuliqbal', true, () => { });
  } else {
    window.open('https://hivesigner.com/sign/account-witness-vote?witness=reazuliqbal&approve=1', '_blank');
  }
}