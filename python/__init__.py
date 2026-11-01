class _Plugin:
    _instance = None
    _plugin = None
    _wasm_path: str = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(_Plugin, cls).__new__(cls)
        return cls._instance

    @classmethod
    def configure(cls, wasm_path: str):
        """Set the path to the WASM plugin binary."""
        cls._wasm_path = wasm_path
        cls._plugin = None  # Reset so next access reloads
        cls._instance = None

    @property
    def plugin(self):
        if self._plugin is None:
            if self._wasm_path is None:
                raise RuntimeError("Call _Plugin.configure(wasm_path)")
            import extism
            with open(self._wasm_path, 'rb') as f:
                wasm_bytes = f.read()
            _Plugin._plugin = extism.Plugin(wasm_bytes, wasi=True)
        return self._plugin