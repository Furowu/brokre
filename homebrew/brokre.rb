class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.5"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.5/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "244e9a53fb29b72b7d8aa9fafe5507a7b394f9a0c737abd1e928d0cdd39fbf8f"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.5/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "7ea1ec32176c564287adc4d179311d5c08bc115d7a39a79d81e5fd8176e02c61"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.5/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "cd30cd1d5e61d8ba109d0097e8f0594f6c9845ba0614c37a7d9454fecfac33f4"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.5/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "22f5b4bc4c58f83c113cad9abfd8a9fd012af423dc460aa3f9f93f885ae29f16"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
