using System;

namespace USBGuardian
{
    internal sealed class ContainmentController
    {
        private readonly InputContainmentManager _containment;

        public ContainmentController(InputContainmentManager containment)
        {
            _containment = containment;
        }

        public ContainmentSession Enter(string reason)
        {
            _containment.Activate(reason);
            return new ContainmentSession(_containment, reason);
        }

        internal readonly struct ContainmentSession : IDisposable
        {
            private readonly InputContainmentManager? _manager;
            private readonly string _reason;

            public ContainmentSession(InputContainmentManager manager, string reason)
            {
                _manager = manager;
                _reason = reason;
            }

            public void Dispose() => _manager?.Deactivate(_reason);
        }
    }
}
