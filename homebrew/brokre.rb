class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.30"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.30/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "01e8e1c073764ac2b2e286f251e5e75b06d02b69661f9d82b66920ba1806fccc"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.30/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "98982f67f3c3bc0fca15e77de1d25db3d4b73350037b86f264cd1b61452bff4b"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.30/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "049ba5e20dcede2c5e7c34f77d51254924f6cf803faaa9b8f7e6279255a33c7a"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.30/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "5c112060687a0373bdf912154dce829cfa18606cab569e8f35b99478e47d07ca"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
