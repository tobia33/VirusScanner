# file report_spec.rb

require 'rails_helper'

RSpec.describe Report, type: :model do
    subject { described_class.new }
        context 'Attributes' do
        describe 'attributes' do
            it 'has sha256 attribute' do
              expect(subject).to respond_to(:sha256)
            end
        
            it 'has url attribute' do
              expect(subject).to respond_to(:url)
            end
        
            it 'has content attribute' do
              expect(subject).to respond_to(:content)
            end
            it 'has score attribute' do
                expect(subject).to respond_to(:score)
            end
          
            it 'has group_id attribute' do
                expect(subject).to respond_to(:group_id)
            end

            it 'has user_id attribute' do
                expect(subject).to respond_to(:user_id)
            end

            it 'has created_at attribute' do
                expect(subject).to respond_to(:created_at)
            end
            it 'has updated_at attribute' do
                expect(subject).to respond_to(:updated_at)
            end
        end
        describe 'database indexes' do
            it 'has an index on group_id' do
              expect(subject.class.connection.index_exists?(:reports, :group_id)).to be_truthy
            end
        
            it 'has an index on user_id' do
              expect(subject.class.connection.index_exists?(:reports, :user_id)).to be_truthy
            end
        end
    end # end Attributes
end