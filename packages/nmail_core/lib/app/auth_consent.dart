import 'package:ndk/ndk.dart';


/// Resolves the [Ndk] lazily: at bootstrap the handler exists before the
/// instance does, and the first auth question only fires once it runs.
typedef NdkGetter = Ndk Function();

/// The account's own relays and Blossom servers, as (relay urls, server urls).
typedef OwnHostLists = ({Set<String> relays, Set<String> servers});

/// Loads the lists the logged-in account itself published. Returning null
/// (or throwing) means "unknown" and the caller stays conservative.
typedef OwnHostListsLoader = Future<OwnHostLists?> Function(String pubkey);

/// Answers ndk's `authHandler`: may this relay or Blossom server see the
/// account's pubkey?
///
/// A yes lets the host tie the account to the connection's IP, so the answer
/// is only yes for hosts the account itself published (NIP-65 kind 10002,
/// DM relays kind 10050, Blossom servers kind 10063/10013) and for the
/// app's built-in defaults. Relays and servers that arrive from other
/// people's lists — discovery results, a recipient's DM relays, attachment
/// hosts named in incoming mail — get a no, and the request stays on the
/// anonymous connection instead.
///
/// Fail-closed: while the own lists are still loading, or when they cannot
/// be read, anything outside the defaults is a no.
class AuthConsent {
  AuthConsent({
    required OwnHostListsLoader loadOwnLists,
    Set<String> defaults = const {},
    DateTime Function()? now,
  }) : _loadOwnLists = loadOwnLists,
       _defaults = defaults.map(_normalize).toSet(),
       _now = now ?? DateTime.now;

  /// Loader wired to ndk's NIP-65 and Blossom-server-list use cases.
  static OwnHostListsLoader loaderFor(NdkGetter ndk) => (pubkey) async {
    final n = ndk();
    final relays = await n.userRelayLists.getSingleUserRelayList(pubkey);
    final servers = await n.blossomUserServerList.getUserServerList(
      pubkeys: [pubkey],
    );
    return (
      relays: relays?.relays.keys.toSet() ?? <String>{},
      servers: servers?.toSet() ?? <String>{},
    );
  };

  final OwnHostListsLoader _loadOwnLists;
  final Set<String> _defaults;

  String? _loadedFor;
  Set<String> _allowed = const {};
  bool _loading = false;
  DateTime? _lastFailedAt;
  DateTime Function() _now;

  /// After a failed own-list load, wait this long before asking again, so
  /// one offline moment does not turn into a query per auth question.
  static const _failureRetryDelay = Duration(seconds: 30);

  static const _defaultPorts = {'ws': 80, 'http': 80, 'wss': 443, 'https': 443};

  /// Scheme + host + explicit non-default port + path (trailing '/'). Port
  /// and case forms of the same host must compare equal; unparseable input
  /// falls back to the trimmed string.
  static String _normalize(String url) {
    final trimmed = url.trim().toLowerCase();
    final parsed = Uri.tryParse(trimmed);
    if (parsed != null && parsed.hasScheme && parsed.host.isNotEmpty) {
      final defaultPort = _defaultPorts[parsed.scheme];
      final port = parsed.hasPort && parsed.port != defaultPort
          ? ':${parsed.port}'
          : '';
      final path = parsed.path == '/' ? '' : parsed.path;
      return '${parsed.scheme}://${parsed.host}$port$path';
    }
    var u = trimmed;
    while (u.endsWith('/')) {
      u = u.substring(0, u.length - 1);
    }
    return u;
  }

  /// May [url] be sent [pubkey]'s identity? The `authHandler` signature.
  Future<bool> call(String url, String pubkey) => allow(url, pubkey);

  Future<bool> allow(String url, String pubkey) async {
    final host = _normalize(url);
    // Defaults never need the network, so answering them cannot recurse into
    // ndk while ndk is the one asking.
    if (_defaults.contains(host)) {
      return true;
    }
    if (_loading) {
      // An auth question arrived while the own lists are being fetched (the
      // fetch itself hit a challenging relay). Stay anonymous this once
      // rather than recurse.
      return false;
    }
    final now = _now();
    if (_lastFailedAt != null &&
        now.difference(_lastFailedAt!) < _failureRetryDelay) {
      // The last load just failed; answer from the cache instead of
      // hammering the loader on every auth question.
      return _allowed.contains(host);
    }
    if (_loadedFor != pubkey) {
      _loading = true;
      try {
        final own = await _loadOwnLists(pubkey);
        _allowed = {
          ..._defaults,
          ...?own?.relays.map(_normalize),
          ...?own?.servers.map(_normalize),
        };
        _loadedFor = pubkey;
        _lastFailedAt = null;
      } catch (_) {
        // Unknown lists fail closed. Do not cache the failure as an answer:
        // own relays stay deniable until restart, so retry after a cooldown
        // instead.
        _allowed = _defaults;
        _lastFailedAt = now;
      } finally {
        _loading = false;
      }
    }
    return _allowed.contains(host);
  }
}
